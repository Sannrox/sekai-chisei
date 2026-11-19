//! Bounded pagination over rows whose visibility is known only after loading.

/// Server-side ceiling on raw rows one page request may scan, whatever limit
/// and offset the caller sends.
pub(crate) const MAX_SCAN_ROWS: usize = 10_000;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum VisiblePageError<E> {
    Fetch(E),
    ScanBudgetExhausted,
}

/// Return one page of visible rows without allowing invisible rows to make a
/// short page look like the end of storage.
///
/// `fetch` receives a raw storage limit and offset. The scan budget bounds the
/// work performed when most rows are invisible and never exceeds
/// [`MAX_SCAN_ROWS`] plus one probe row; exhausting it before filling the
/// requested page fails closed unless storage ends exactly at the budget.
pub(crate) fn scan_visible_page<T, E>(
    visible_limit: usize,
    visible_offset: usize,
    mut fetch: impl FnMut(i32, i32) -> Result<Vec<T>, E>,
    mut is_visible: impl FnMut(&T) -> bool,
) -> Result<Vec<T>, VisiblePageError<E>> {
    let batch_size = visible_limit.clamp(50, 200);
    let max_scan = visible_offset
        .saturating_add(visible_limit)
        .saturating_mul(10)
        .clamp(200, MAX_SCAN_ROWS);
    // RPC page limits are positive i32 values but are not globally capped.
    // Reserve at most one bounded fetch batch so a large caller-supplied limit
    // cannot force an eager, process-sized allocation.
    let mut visible = Vec::with_capacity(visible_limit.min(batch_size));
    let mut scanned = 0usize;
    let mut skipped = 0usize;
    let mut scan_offset = 0i32;
    let mut reached_end = false;

    while visible.len() < visible_limit && scanned < max_scan {
        let take = batch_size.min(max_scan - scanned);
        let batch = fetch(take as i32, scan_offset).map_err(VisiblePageError::Fetch)?;
        // A batch shorter than requested means storage has no more rows.
        reached_end = batch.len() < take;
        if batch.is_empty() {
            break;
        }
        scan_offset = scan_offset.saturating_add(batch.len() as i32);
        scanned = scanned.saturating_add(batch.len());
        for row in batch {
            if !is_visible(&row) {
                continue;
            }
            if skipped < visible_offset {
                skipped += 1;
                continue;
            }
            visible.push(row);
            if visible.len() >= visible_limit {
                break;
            }
        }
    }

    // The budget ran out on a full batch: one probe row decides whether
    // storage ended exactly at the budget or the short page hides more rows.
    if visible.len() < visible_limit
        && scanned >= max_scan
        && !reached_end
        && !fetch(1, scan_offset)
            .map_err(VisiblePageError::Fetch)?
            .is_empty()
    {
        Err(VisiblePageError::ScanBudgetExhausted)
    } else {
        Ok(visible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(count: i32) -> Vec<i32> {
        (0..count).collect()
    }

    #[test]
    fn invisible_rows_do_not_consume_the_visible_limit() {
        let source = rows(120);
        let page = scan_visible_page(
            3,
            0,
            |limit, offset| {
                Ok::<_, ()>(
                    source
                        .iter()
                        .skip(offset as usize)
                        .take(limit as usize)
                        .copied()
                        .collect(),
                )
            },
            |row| row % 20 == 0,
        )
        .unwrap();

        assert_eq!(page, vec![0, 20, 40]);
    }

    #[test]
    fn offset_counts_only_visible_rows() {
        let source = rows(120);
        let page = scan_visible_page(
            2,
            2,
            |limit, offset| {
                Ok::<_, ()>(
                    source
                        .iter()
                        .skip(offset as usize)
                        .take(limit as usize)
                        .copied()
                        .collect(),
                )
            },
            |row| row % 10 == 0,
        )
        .unwrap();

        assert_eq!(page, vec![20, 30]);
    }

    #[test]
    fn storage_exhaustion_returns_a_short_page() {
        let source = rows(3);
        let page = scan_visible_page(
            10,
            0,
            |limit, offset| {
                Ok::<_, ()>(
                    source
                        .iter()
                        .skip(offset as usize)
                        .take(limit as usize)
                        .copied()
                        .collect(),
                )
            },
            |_| true,
        )
        .unwrap();

        assert_eq!(page, source);
    }

    #[test]
    fn unbounded_client_limit_does_not_drive_result_preallocation() {
        let page = scan_visible_page(
            i32::MAX as usize,
            0,
            |_, _| Ok::<_, ()>(Vec::<i32>::new()),
            |_| true,
        )
        .unwrap();

        assert!(page.is_empty());
        assert!(page.capacity() <= 200);
    }

    #[test]
    fn scan_budget_exhaustion_fails_closed() {
        let source = rows(250);
        let error = scan_visible_page(
            1,
            0,
            |limit, offset| {
                Ok::<_, ()>(
                    source
                        .iter()
                        .skip(offset as usize)
                        .take(limit as usize)
                        .copied()
                        .collect(),
                )
            },
            |_| false,
        )
        .unwrap_err();

        assert_eq!(error, VisiblePageError::ScanBudgetExhausted);
    }

    #[test]
    fn storage_ending_exactly_at_the_budget_returns_a_short_page() {
        // One visible row in 200 raw rows: the budget (200) is spent on a
        // full last batch, and the probe finds no further rows.
        for count in [200, 150] {
            let source = rows(count);
            let page = scan_visible_page(
                5,
                0,
                |limit, offset| {
                    Ok::<_, ()>(
                        source
                            .iter()
                            .skip(offset as usize)
                            .take(limit as usize)
                            .copied()
                            .collect(),
                    )
                },
                |row| *row == 7,
            )
            .unwrap();

            assert_eq!(page, vec![7], "{count} rows");
        }
    }

    #[test]
    fn caller_limit_and_offset_cannot_raise_the_scan_ceiling() {
        for (limit, offset) in [(i32::MAX as usize, 0), (1, i32::MAX as usize)] {
            let mut scanned = 0usize;
            let error = scan_visible_page(
                limit,
                offset,
                |limit, offset| {
                    scanned += limit as usize;
                    // Stop a runaway scan so a missing ceiling fails fast. The
                    // ceiling allows one probe row past the budget.
                    if scanned > MAX_SCAN_ROWS + 1 {
                        return Err(());
                    }
                    Ok((offset..offset.saturating_add(limit)).collect::<Vec<i32>>())
                },
                |_| false,
            )
            .unwrap_err();

            assert_eq!(error, VisiblePageError::ScanBudgetExhausted);
            assert!(scanned <= MAX_SCAN_ROWS + 1, "scanned {scanned} rows");
        }
    }
}
