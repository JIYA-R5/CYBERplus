import React, { useState, useEffect } from 'react';
import { Routes, Route, useNavigate } from 'react-router-dom';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { OverviewPage } from './pages/OverviewPage';
import { LiveNetworkPage } from './pages/LiveNetworkPage';
import { TrafficAnalyticsPage } from './pages/TrafficAnalyticsPage';
import { ThreatDetectionPage } from './pages/ThreatDetectionPage';
import { SecurityAlertsPage } from './pages/SecurityAlertsPage';
import { HostsPage } from './pages/HostsPage';
import { InvestigationPage } from './pages/InvestigationPage';
import { ModelInsightsPage } from './pages/ModelInsightsPage';
import { SettingsPage } from './pages/SettingsPage';
import { useWebSocket } from './hooks/useWebSocket';
import { api } from './services/api';
import { CollectorStatus, DataSource, TimeRange } from './types';

export const App: React.FC = () => {
  const navigate = useNavigate();

  // Layout & Theme state
  const [collapsed, setCollapsed] = useState<boolean>(false);
  const [isDarkTheme, setIsDarkTheme] = useState<boolean>(true);
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selected Host for cross-page drilldown
  const [selectedHostIp, setSelectedHostIp] = useState<string | null>(null);

  // Collector status
  const [collectorStatus, setCollectorStatus] = useState<CollectorStatus | null>(null);
  const [dataSource, setDataSource] = useState<DataSource>('SIMULATION');

  // Real-time WebSocket hook
  const {
    status: wsStatus,
    events: liveEvents,
    alerts: liveAlerts,
    isPaused,
    togglePause,
    lastEventTime,
  } = useWebSocket({ maxEvents: 200 });

  // Poll collector status periodically
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const status = await api.getCollectorStatus();
        setCollectorStatus(status);
        if (status.mode === 'live') {
          setDataSource('LIVE');
        } else if (status.mode === 'pcap') {
          setDataSource('PCAP REPLAY');
        } else {
          setDataSource('SIMULATION');
        }
      } catch (err) {
        console.debug('Collector status poll:', err);
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 4000);
    return () => clearInterval(interval);
  }, []);

  const toggleTheme = () => {
    setIsDarkTheme((prev) => {
      const next = !prev;
      if (next) {
        document.documentElement.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
      }
      return next;
    });
  };

  const handleSelectHost = (ip: string) => {
    setSelectedHostIp(ip);
    navigate('/hosts');
  };

  const handleNavigateToAlerts = () => {
    navigate('/alerts');
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] text-slate-100 flex">
      {/* Collapsible Left Sidebar */}
      <Sidebar
        collapsed={collapsed}
        onToggle={() => setCollapsed(!collapsed)}
        openAlertsCount={liveAlerts.length}
        collectorStatus={collectorStatus}
      />

      {/* Main Layout Area */}
      <div
        className={`flex-1 transition-all duration-300 flex flex-col ${
          collapsed ? 'ml-20' : 'ml-64'
        }`}
      >
        {/* Top Header */}
        <Header
          collapsed={collapsed}
          timeRange={timeRange}
          onTimeRangeChange={setTimeRange}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          dataSource={dataSource}
          collectorStatus={collectorStatus}
          wsStatus={wsStatus}
          lastEventTime={lastEventTime}
          isPaused={isPaused}
          onTogglePause={togglePause}
          isDarkTheme={isDarkTheme}
          onToggleTheme={toggleTheme}
          unreadAlertsCount={liveAlerts.length}
        />

        {/* Page Content Body */}
        <main className="flex-1 p-6 mt-16 max-w-7xl w-full mx-auto">
          <Routes>
            <Route
              path="/"
              element={
                <OverviewPage
                  timeRange={timeRange}
                  onSelectHost={handleSelectHost}
                  onNavigateToAlerts={handleNavigateToAlerts}
                />
              }
            />
            <Route
              path="/overview"
              element={
                <OverviewPage
                  timeRange={timeRange}
                  onSelectHost={handleSelectHost}
                  onNavigateToAlerts={handleNavigateToAlerts}
                />
              }
            />
            <Route
              path="/live-network"
              element={
                <LiveNetworkPage
                  liveEvents={liveEvents}
                  isPaused={isPaused}
                  onTogglePause={togglePause}
                  onSelectHost={handleSelectHost}
                />
              }
            />
            <Route
              path="/analytics"
              element={<TrafficAnalyticsPage timeRange={timeRange} />}
            />
            <Route path="/threats" element={<ThreatDetectionPage />} />
            <Route path="/alerts" element={<SecurityAlertsPage />} />
            <Route
              path="/hosts"
              element={<HostsPage initialHostIp={selectedHostIp} />}
            />
            <Route path="/investigation" element={<InvestigationPage />} />
            <Route path="/models" element={<ModelInsightsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route
              path="*"
              element={
                <OverviewPage
                  timeRange={timeRange}
                  onSelectHost={handleSelectHost}
                  onNavigateToAlerts={handleNavigateToAlerts}
                />
              }
            />
          </Routes>
        </main>
      </div>
    </div>
  );
};

export default App;
