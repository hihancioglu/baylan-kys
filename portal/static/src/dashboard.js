async function loadStandardChart() {
  const resp = await fetch('/api/dashboard/standard-summary');
  const data = await resp.json();
  const labels = data.map(d => d.standard);
  const counts = data.map(d => d.count);
  const canvas = document.getElementById('standard-chart');
  if (!canvas) return;
  new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [{ label: 'Documents', data: counts }]
    }
  });
}

loadStandardChart();
