import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from 'chart.js';

// Register ChartJS components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

ChartJS.defaults.color = '#E5E7EB';
ChartJS.defaults.borderColor = 'rgba(255,255,255,0.10)';
if (ChartJS.defaults.plugins?.legend?.labels) {
  ChartJS.defaults.plugins.legend.labels.color = '#E5E7EB';
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
