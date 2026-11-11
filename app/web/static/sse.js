// SSE-клиент (FR-3.13.11) с автопереподключением и polling-fallback.
// EventSource сам переподключается; при повторных сбоях вызывается onFallback.

export function connectEvents({ onEvent, onFallback } = {}) {
  if (typeof EventSource === 'undefined') {
    if (onFallback) onFallback();
    return null;
  }
  let failures = 0;
  const source = new EventSource('/api/v1/events');
  source.onopen = () => { failures = 0; };
  source.onerror = () => {
    failures += 1;
    // 4 последовательных разрыва подряд → считаем SSE недоступным
    if (failures >= 4 && onFallback) {
      source.close();
      onFallback();
    }
  };
  source.onmessage = (e) => {
    try { onEvent && onEvent(JSON.parse(e.data)); } catch { /* malformed frame */ }
  };
  // Именованные типы событий — так же парсим и передаём в onEvent
  for (const type of ['server.status', 'operation.progress', 'traffic.sample']) {
    source.addEventListener(type, (e) => {
      try { onEvent && onEvent(JSON.parse(e.data)); } catch { /* malformed frame */ }
    });
  }
  return source;
}

// Fallback: периодический polling статусов серверов.
export function startPolling(intervalMs, handler) {
  const timer = setInterval(handler, intervalMs);
  handler();
  return () => clearInterval(timer);
}
