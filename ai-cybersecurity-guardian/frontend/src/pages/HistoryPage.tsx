import { AnimatePresence } from 'framer-motion';
import { motion } from 'framer-motion';
import { ChevronLeft, ChevronRight, Copy, History, Search } from 'lucide-react';
import { useState } from 'react';
import toast from 'react-hot-toast';
import { useHistory, HISTORY_PAGE_SIZE } from '@/hooks/useHistory';
import { RiskBadge } from '@/components/ui/Badge';
import { Card } from '@/components/ui/Card';
import { EmptyState, ErrorState } from '@/components/ui/EmptyState';
import { Modal } from '@/components/ui/Modal';
import { Skeleton } from '@/components/ui/Skeleton';
import { getErrorMessage } from '@/lib/api';
import type { URLScanSummary } from '@/types/api';
import { formatDate, timeAgo, truncateUrl } from '@/lib/utils';
import { useNavigate } from 'react-router-dom';

// ---------------------------------------------------------------------------
// Table row
// ---------------------------------------------------------------------------

function HistoryRow({ item, onClick }: { item: URLScanSummary; onClick: () => void }) {
  const copyUrl = (e: React.MouseEvent) => {
    e.stopPropagation();
    void navigator.clipboard.writeText(item.url).then(() => toast.success('URL copied'));
  };

  return (
    <motion.tr
      className="history-row"
      onClick={onClick}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.2 }}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === 'Enter') onClick(); }}
    >
      <td className="history-cell history-cell-url">
        <span title={item.url} className="history-url-text">
          {truncateUrl(item.url, 60)}
        </span>
        <button
          className="history-copy-btn"
          onClick={copyUrl}
          aria-label="Copy URL"
          title="Copy URL"
        >
          <Copy size={13} />
        </button>
      </td>
      <td className="history-cell history-cell-score">
        <span className="history-score" style={{
          color: item.risk_score > 75 ? 'var(--color-critical)' :
                 item.risk_score > 50 ? 'var(--color-danger)' :
                 item.risk_score > 25 ? 'var(--color-warning)' : 'var(--color-safe)',
        }}>
          {item.risk_score}
        </span>
      </td>
      <td className="history-cell">
        <RiskBadge classification={item.classification} size="sm" />
      </td>
      <td className="history-cell history-cell-mono">
        {item.analyzer_version}
      </td>
      <td className="history-cell history-cell-time" title={formatDate(item.created_at)}>
        {timeAgo(item.created_at)}
      </td>
    </motion.tr>
  );
}

// ---------------------------------------------------------------------------
// Main HistoryPage
// ---------------------------------------------------------------------------

export default function HistoryPage() {
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState('');
  const [selectedItem, setSelectedItem] = useState<URLScanSummary | null>(null);
  const navigate = useNavigate();

  const { data, isLoading, isError, error } = useHistory(offset);

  const filtered = (data?.items ?? []).filter((item) =>
    search.trim() === '' || item.url.toLowerCase().includes(search.toLowerCase()),
  );

  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / HISTORY_PAGE_SIZE);
  const currentPage = Math.floor(offset / HISTORY_PAGE_SIZE) + 1;

  if (isError) {
    return (
      <div className="page-container">
        <Card>
          <ErrorState
            title="Could not load scan history"
            description={getErrorMessage(error)}
            action={{ label: 'Retry', onClick: () => window.location.reload() }}
          />
        </Card>
      </div>
    );
  }

  return (
    <div className="page-container">
      {/* Search + pagination header */}
      <div className="history-header">
        <div className="history-search-wrap">
          <Search size={15} style={{ color: 'var(--color-text-muted)' }} aria-hidden="true" />
          <input
            className="history-search"
            type="search"
            placeholder="Filter by URL..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Filter scan history"
          />
        </div>
        {total > 0 && (
          <div className="history-count">
            {total} scan{total !== 1 ? 's' : ''} total
          </div>
        )}
      </div>

      <Card padding="none">
        {isLoading ? (
          <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 12 }}>
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} height={44} />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<History size={40} />}
            title={search ? 'No matching scans' : 'No scan history yet'}
            description={search ? 'Try a different search term' : 'Analyze your first URL to populate your history'}
            action={!search ? { label: 'Analyze a URL', onClick: () => navigate('/scan') } : undefined}
          />
        ) : (
          <div className="history-table-wrap">
            <table className="history-table" aria-label="Scan history">
              <thead>
                <tr>
                  <th className="history-th">URL</th>
                  <th className="history-th">Score</th>
                  <th className="history-th">Risk</th>
                  <th className="history-th">Analyzer</th>
                  <th className="history-th">Scanned</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((item) => (
                  <HistoryRow
                    key={item.id}
                    item={item}
                    onClick={() => setSelectedItem(item)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="history-pagination">
          <button
            className="pagination-btn"
            onClick={() => setOffset((o) => Math.max(0, o - HISTORY_PAGE_SIZE))}
            disabled={offset === 0}
            aria-label="Previous page"
          >
            <ChevronLeft size={16} />
          </button>
          <span className="pagination-info">
            Page {currentPage} of {totalPages}
          </span>
          <button
            className="pagination-btn"
            onClick={() => setOffset((o) => o + HISTORY_PAGE_SIZE)}
            disabled={currentPage >= totalPages}
            aria-label="Next page"
          >
            <ChevronRight size={16} />
          </button>
        </div>
      )}

      {/* Detail modal */}
      <AnimatePresence>
        {selectedItem && (
          <Modal
            isOpen
            onClose={() => setSelectedItem(null)}
            title="Scan Summary"
            maxWidth="640px"
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div>
                <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginBottom: 4 }}>Analyzed URL</p>
                <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--color-cyan)', wordBreak: 'break-all' }}>
                  {selectedItem.url}
                </p>
              </div>
              <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
                <div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginBottom: 4 }}>Risk Score</p>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '2rem', color:
                    selectedItem.risk_score > 75 ? 'var(--color-critical)' :
                    selectedItem.risk_score > 50 ? 'var(--color-danger)' :
                    selectedItem.risk_score > 25 ? 'var(--color-warning)' : 'var(--color-safe)',
                  }}>
                    {selectedItem.risk_score}
                  </span>
                </div>
                <div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginBottom: 4 }}>Classification</p>
                  <RiskBadge classification={selectedItem.classification} />
                </div>
                <div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginBottom: 4 }}>Analyzer</p>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--color-text-secondary)' }}>
                    {selectedItem.analyzer_version}
                  </span>
                </div>
              </div>
              <div>
                <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                  Scanned {formatDate(selectedItem.created_at)}
                </p>
              </div>
              <button
                className="scanner-example-btn"
                onClick={() => { void navigator.clipboard.writeText(selectedItem.url).then(() => toast.success('URL copied')); }}
                style={{ alignSelf: 'flex-start' }}
              >
                <Copy size={13} /> Copy URL
              </button>
            </div>
          </Modal>
        )}
      </AnimatePresence>
    </div>
  );
}
