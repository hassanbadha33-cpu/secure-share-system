/* Activity Log page logic */
'use strict';

let logsPage = 1;
let logsSearch = '';

initApp('logs', 'Activity Log', 'Every upload, download, share and access attempt is recorded', async (user) => {
  const content = document.getElementById('content');

  content.innerHTML = `
    <div class="toolbar">
      <div class="search-box">
        <span class="icon">${icon('search')}</span>
        <input type="search" id="log-search" placeholder="Search actions, details, usernames…">
      </div>
      <span class="badge">${user.role === 'admin' ? 'Viewing all users' : 'Viewing your activity'}</span>
    </div>
    <div class="card" id="log-card"><div class="empty"><div class="big">${icon('clock')}</div><p>Loading activity…</p></div></div>
    <div class="pagination" id="pagination"></div>
  `;

  const searchInput = document.getElementById('log-search');
  let debounce;
  searchInput.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => { logsSearch = searchInput.value.trim(); logsPage = 1; loadLogs(); }, 350);
  });

  async function loadLogs() {
    const card = document.getElementById('log-card');
    let data;
    try {
      data = await API.get(`/api/logs?page=${logsPage}&per_page=20&search=${encodeURIComponent(logsSearch)}`);
    } catch (err) {
      card.innerHTML = `<div class="empty">${escapeHtml(err.message)}</div>`;
      return;
    }

    if (!data.logs.length) {
      card.innerHTML = `<div class="empty"><div class="big">${icon('activity')}</div><p>No activity found.</p></div>`;
      document.getElementById('pagination').innerHTML = '';
      return;
    }

    card.innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th>Action</th><th>User</th><th>Details</th><th>IP Address</th><th>Time</th></tr></thead>
      <tbody>${data.logs.map((l) => `
        <tr>
          <td><span class="badge">${escapeHtml(actionLabel(l.action))}</span></td>
          <td>${escapeHtml(l.username)}</td>
          <td class="cell-sub">${escapeHtml(l.details || '—')}</td>
          <td class="mono cell-sub">${escapeHtml(l.ip_address || '—')}</td>
          <td class="cell-sub">${formatDate(l.created_at)}</td>
        </tr>`).join('')}
      </tbody></table></div>`;

    renderPagination(document.getElementById('pagination'), {
      page: data.page, total: data.total, per_page: data.per_page,
      onPage: (p) => { logsPage = p; loadLogs(); },
    });
  }

  loadLogs();
});
