import React from "react";

const App: React.FC = () => {
  return (
    <div className="app">
      <header className="app-header">
        <h1>Grip Network Monitor</h1>
      </header>
      <main className="app-main">
        <div className="dashboard">
          <h2>Network Statistics</h2>
          <div className="stats-container">
            {/* Stats will be added here */}
          </div>
        </div>
      </main>
    </div>
  );
};

export default App;
