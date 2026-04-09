import React from 'react';
import Dashboard from './components/Dashboard';

function App() {
  return (
    <div style={{ fontFamily: 'Arial, sans-serif', padding: '20px', backgroundColor: '#f4f4f4', minHeight: '100vh' }}>
      <h1 style={{ textAlign: 'center', color: '#333' }}>Attack Prevention & Detection System</h1>
      <Dashboard />
    </div>
  );
}

export default App;
