import React, { useState, useEffect, useRef } from 'react';
import {
  Globe,
  ShieldAlert,
  Search,
  Filter,
  MapPin,
  Compass,
  AlertTriangle,
  Server,
  Activity,
  Layers,
  Info,
  ExternalLink,
  ChevronRight,
  Database,
  Radio,
  Clock,
  Crosshair,
  CheckCircle2,
  RefreshCw,
  TrendingUp,
} from 'lucide-react';
import { api } from '../services/api';
import { ThreatMapData, ThreatMarker, CountryAggregate, LocalNetworkHost, IpIntelligence } from '../types';
import Plotly from 'plotly.js-dist-min';

export const ThreatIntelligencePage: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'geo' | 'topology' | 'lookup'>('geo');
  const [data, setData] = useState<ThreatMapData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [timeWindow, setTimeWindow] = useState<string>('Last 24 Hours');
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [countryFilter, setCountryFilter] = useState<string>('All');
  const [categoryFilter, setCategoryFilter] = useState<string>('All');

  // Selected Country for Choropleth Intelligence Panel
  const [selectedCountry, setSelectedCountry] = useState<CountryAggregate | null>(null);

  // Selected Marker for City Pin Detail Drawer
  const [selectedMarker, setSelectedMarker] = useState<ThreatMarker | null>(null);

  // Map Container Ref for Plotly
  const mapContainerRef = useRef<HTMLDivElement>(null);

  // IP Lookup Inspector State
  const [lookupIp, setLookupIp] = useState<string>('128.30.52.100');
  const [lookupResult, setLookupResult] = useState<{
    ip: string;
    intelligence: IpIntelligence;
    recent_flows_count: number;
    related_incidents_count: number;
    recent_flows: any[];
    incidents: any[];
  } | null>(null);
  const [lookupLoading, setLookupLoading] = useState<boolean>(false);
  const [lookupError, setLookupError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getThreatMap({
        severity: severityFilter,
        category: categoryFilter,
        country: countryFilter,
        timeRange: timeWindow,
      });
      setData(res);

      if (res.country_aggregates && res.country_aggregates.length > 0) {
        // If current selected country still exists in new data, keep it, otherwise pick top
        const existing = selectedCountry ? res.country_aggregates.find(c => c.country.toLowerCase() === selectedCountry.country.toLowerCase()) : null;
        setSelectedCountry(existing || res.country_aggregates[0]);
      } else {
        setSelectedCountry(null);
      }

      if (res.markers && res.markers.length > 0) {
        setSelectedMarker(res.markers[0]);
      }
    } catch (e: any) {
      console.error('Failed to load threat map data', e);
      setError(e.message || 'Error fetching threat map data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [timeWindow, severityFilter, countryFilter, categoryFilter]);

  const handleRunLookup = async (ipToSearch?: string) => {
    const target = ipToSearch || lookupIp;
    if (!target.trim()) return;
    try {
      setLookupLoading(true);
      setLookupError(null);
      const res = await api.lookupIp(target.trim());
      setLookupResult(res);
    } catch (e: any) {
      setLookupError(e.message || 'Failed to lookup IP');
    } finally {
      setLookupLoading(false);
    }
  };

  const getMarkerSeverity = (m?: any): string => {
    return m?.severity || m?.max_severity || 'Medium';
  };

  const getSeverityColor = (sev?: string) => {
    switch ((sev || 'medium').toLowerCase()) {
      case 'critical':
        return '#EF4444';
      case 'high':
        return '#F59E0B';
      case 'medium':
        return '#3B82F6';
      case 'low':
        return '#10B981';
      default:
        return '#06B6D4';
    }
  };

  const stats = data?.statistics || {
    total_geolocated_sources: data?.total_public_markers || 0,
    countries_detected: data?.country_aggregates?.length || 0,
    total_suspicious_events: data?.total_incidents_analyzed || 0,
    unlocated_source_ips: data?.total_local_hosts || 0,
    high_critical_events: 0,
  };

  // Render Interactive Plotly Choropleth Map with Red/Pink Threat Gradient
  useEffect(() => {
    if (activeSubTab !== 'geo' || !mapContainerRef.current) return;

    const countries = data?.country_aggregates || [];
    const markers = data?.markers || [];

    // Red/pink gradient based on actual suspicious event intensity:
    // Low: Dark red (#450A0A)
    // Medium: Deep medium red (#991B1B)
    // High: Bright red (#EF4444)
    // Critical: Vivid pink/red (#F43F5E / #FB7185)
    const redPinkColorscale: [number, string][] = [
      [0.0, '#38040E'],   // Deepest dark red
      [0.25, '#670A1A'],  // Low: Dark red
      [0.5, '#A8132B'],   // Medium: Medium red
      [0.75, '#EF233C'],  // High: Bright red
      [1.0, '#FF4D6D']    // Critical: Vivid pink/red
    ];

    const traces: any[] = [];

    if (countries.length > 0) {
      const choroplethTrace: any = {
        type: 'choropleth',
        locationmode: 'country names',
        locations: countries.map(c => c.country),
        z: countries.map(c => Math.max(1, c.intensity_score)),
        text: countries.map(c => c.country),
        customdata: countries.map(c => ({
          country: c.country,
          country_code: c.country_code || 'XX',
          intensity: c.intensity_score,
          incident_count: c.incident_count,
          unique_ips: c.unique_ips,
          severity: c.max_severity || 'Medium',
          top_category: c.top_category || 'Suspicious Probe',
        })),
        colorscale: redPinkColorscale,
        autocolorscale: false,
        reversescale: false,
        marker: {
          line: {
            color: '#1E293B',
            width: 0.8,
          },
        },
        colorbar: {
          title: {
            text: 'Threat Intensity',
            font: { color: '#94A3B8', size: 10, family: 'Inter' },
          },
          tickfont: { color: '#94A3B8', size: 9, family: 'JetBrains Mono' },
          bgcolor: 'rgba(15, 23, 42, 0.85)',
          bordercolor: '#1E293B',
          thickness: 12,
          len: 0.6,
          x: 0.98,
          y: 0.5,
        },
        hovertemplate:
          '<span style="font-family:Inter; font-size:12px;">' +
          '<b style="font-size:14px; color:#FFFFFF;">%{customdata.country}</b> (%{customdata.country_code})<br>' +
          '⚡ Threat Intensity Score: <b>%{z}</b><br>' +
          '🚨 Suspicious Events: <b>%{customdata.incident_count}</b><br>' +
          '🌐 Unique Source IPs: <b>%{customdata.unique_ips}</b><br>' +
          '⚠️ Severity Rating: <b>%{customdata.severity}</b><br>' +
          '🎯 Primary Threat: <b>%{customdata.top_category}</b>' +
          '</span><extra></extra>',
      };
      traces.push(choroplethTrace);
    }

    // Precise city coordinates scatter markers overlay
    if (markers.length > 0) {
      const scatterTrace: any = {
        type: 'scattergeo',
        lat: markers.map(m => m.latitude),
        lon: markers.map(m => m.longitude),
        text: markers.map(m => `${m.city || 'Origin'}, ${m.country}`),
        customdata: markers,
        mode: 'markers',
        marker: {
          size: markers.map(m => Math.min(20, Math.max(8, Math.sqrt((m.total_packets || 10) * 1.8)))),
          color: markers.map(m => getSeverityColor(m.severity || m.max_severity)),
          line: {
            color: '#FFFFFF',
            width: 1.5,
          },
          opacity: 0.95,
        },
        hovertemplate:
          '<b>📍 %{text}</b><br>' +
          'Source IP(s): %{customdata.source_ips}<br>' +
          'Max Severity: %{customdata.severity}<br>' +
          'Packet Volume: %{customdata.total_packets}<br>' +
          'Categories: %{customdata.categories}<extra></extra>',
      };
      traces.push(scatterTrace);
    }

    const layout: any = {
      geo: {
        showframe: false,
        showcoastlines: true,
        coastlinecolor: '#1E293B',
        showcountries: true,
        countrycolor: '#1E293B',
        countrywidth: 0.8,
        showland: true,
        landcolor: '#0B132B', // Dark navy for countries without suspicious events
        showocean: true,
        oceancolor: '#070A11', // Deep dark navy ocean
        showlakes: true,
        lakecolor: '#070A11',
        projection: {
          type: 'natural earth',
        },
        bgcolor: '#070A11',
      },
      paper_bgcolor: '#070A11',
      plot_bgcolor: '#070A11',
      margin: { l: 0, r: 0, t: 5, b: 5 },
      height: 480,
      showlegend: false,
    };

    const config: any = {
      responsive: true,
      displayModeBar: false,
    };

    Plotly.newPlot(mapContainerRef.current, traces, layout, config).then(() => {
      const plotEl = mapContainerRef.current as any;
      if (!plotEl) return;

      plotEl.removeAllListeners?.('plotly_click');
      plotEl.on('plotly_click', (eventData: any) => {
        if (!eventData || !eventData.points || eventData.points.length === 0) return;
        const pt = eventData.points[0];
        if (pt.data.type === 'choropleth') {
          const clickedCountryName = pt.location;
          const match = (data?.country_aggregates || []).find(
            c => c.country.toLowerCase() === String(clickedCountryName).toLowerCase()
          );
          if (match) {
            setSelectedCountry(match);
          }
        } else if (pt.data.type === 'scattergeo') {
          setSelectedMarker(pt.customdata);
          const match = (data?.country_aggregates || []).find(
            c => c.country.toLowerCase() === String(pt.customdata.country).toLowerCase()
          );
          if (match) setSelectedCountry(match);
        }
      });
    });

    const handleResize = () => {
      if (mapContainerRef.current) {
        Plotly.Plots.resize(mapContainerRef.current);
      }
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (mapContainerRef.current) {
        Plotly.purge(mapContainerRef.current);
      }
    };
  }, [data, activeSubTab]);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between p-5 rounded-2xl bg-gradient-to-r from-slate-900/90 via-[#0D1526]/80 to-slate-900/90 border border-slate-800 shadow-xl gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.3)]">
              <Globe className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white tracking-wide flex items-center gap-2">
                Cybersecurity Threat Heat Map & Source IP Intelligence
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Interactive Plotly Choropleth map, MaxMind GeoLite2 geographic intelligence, and SQLite threat intensity.
              </p>
            </div>
          </div>
        </div>

        {/* Sub-tab navigation */}
        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-slate-950/80 border border-slate-800">
          <button
            onClick={() => setActiveSubTab('geo')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              activeSubTab === 'geo'
                ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Choropleth Heat Map</span>
          </button>

          <button
            onClick={() => setActiveSubTab('topology')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              activeSubTab === 'topology'
                ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span>Local Topology ({data?.local_network?.length || 0})</span>
          </button>

          <button
            onClick={() => {
              setActiveSubTab('lookup');
              if (!lookupResult) handleRunLookup();
            }}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              activeSubTab === 'lookup'
                ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span>Source IP Inspector</span>
          </button>
        </div>
      </div>

      {/* Mandatory Specification Notice */}
      <div className="flex items-start gap-3 p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-200 text-xs">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <strong className="font-semibold text-amber-300">IP Geolocation Notice:</strong> IP geolocation is approximate.
          It indicates the estimated location of an IP network, not the identity or precise physical location of a person.
          Do not imply that a source's country or city proves malicious intent.
        </div>
      </div>

      {/* 5 Required Key KPI Statistics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="p-4 rounded-xl bg-[#0F172A]/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Geolocated Sources</span>
            <MapPin className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-1.5 font-mono">{stats.total_geolocated_sources}</div>
          <div className="text-[10px] text-cyan-400 mt-1 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
            Public IPs with coordinates
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A]/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Countries Detected</span>
            <Globe className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-1.5 font-mono">{stats.countries_detected}</div>
          <div className="text-[10px] text-emerald-400 mt-1">Global origin nations</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A]/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Suspicious Events</span>
            <Activity className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-1.5 font-mono">{stats.total_suspicious_events}</div>
          <div className="text-[10px] text-slate-400 mt-1">SQLite verified records</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A]/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Unlocated / Private</span>
            <Server className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-1.5 font-mono">{stats.unlocated_source_ips}</div>
          <div className="text-[10px] text-purple-400 mt-1">RFC 1918 / Local subnets</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A]/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>High & Critical</span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400 mt-1.5 font-mono">{stats.high_critical_events}</div>
          <div className="text-[10px] text-rose-400 mt-1">Priority action required</div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* SUB-TAB 1: GEOGRAPHIC THREAT CHOROPLETH MAP */}
      {/* ===================================================================== */}
      {activeSubTab === 'geo' && (
        <div className="space-y-5">
          {/* Filter Controls Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-slate-900/80 border border-slate-800">
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Filter className="w-3.5 h-3.5 text-cyan-400" /> Filter Telemetry:
              </span>

              {/* Time Window */}
              <select
                value={timeWindow}
                onChange={(e) => setTimeWindow(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="Last 15 Minutes">Last 15 Minutes</option>
                <option value="Last 1 Hour">Last 1 Hour</option>
                <option value="Last 24 Hours">Last 24 Hours</option>
                <option value="Last 7 Days">Last 7 Days</option>
                <option value="All Time">All Time</option>
              </select>

              {/* Severity */}
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="All">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>

              {/* Country */}
              <select
                value={countryFilter}
                onChange={(e) => setCountryFilter(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="All">All Countries</option>
                {data?.country_aggregates?.map((c) => (
                  <option key={c.country} value={c.country}>
                    {c.country} ({c.incident_count} events &bull; wt={c.intensity_score})
                  </option>
                ))}
              </select>

              {/* Category */}
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="All">All Categories</option>
                <option value="Port Scan">Port Scan</option>
                <option value="Brute Force">Brute Force</option>
                <option value="DDoS Surge">DDoS Surge</option>
                <option value="Web Reconnaissance">Web Reconnaissance</option>
                <option value="Data Exfiltration">Data Exfiltration</option>
              </select>
            </div>

            <button
              onClick={fetchData}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
              <span>Refresh Map</span>
            </button>
          </div>

          {/* Map & Country Intelligence Panel Layout */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Left 2 Cols: Plotly World Choropleth Map */}
            <div className="lg:col-span-2 p-5 rounded-2xl bg-[#090D16] border border-slate-800 shadow-xl relative overflow-hidden flex flex-col justify-between">
              {/* Map Canvas Header */}
              <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 mb-2">
                <div className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping"></div>
                  <h3 className="text-sm font-bold text-white tracking-wide">
                    Global Threat Intensity Choropleth Map
                  </h3>
                </div>
                <div className="flex items-center gap-3 text-[11px] text-slate-400 font-mono">
                  <span className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-sm bg-[#38040E]"></span> Low
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-sm bg-[#A8132B]"></span> Medium
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-sm bg-[#EF233C]"></span> High
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-sm bg-[#FF4D6D]"></span> Critical
                  </span>
                </div>
              </div>

              {/* Plotly Interactive Choropleth Container */}
              <div className="relative w-full min-h-[480px] bg-[#070A11] rounded-xl border border-slate-800/50 overflow-hidden flex items-center justify-center">
                {loading && (
                  <div className="absolute inset-0 bg-[#070A11]/70 backdrop-blur-sm z-10 flex items-center justify-center gap-3 text-cyan-400 text-sm font-mono">
                    <RefreshCw className="w-5 h-5 animate-spin" />
                    <span>Rendering Plotly Choropleth Boundaries...</span>
                  </div>
                )}
                <div ref={mapContainerRef} className="w-full h-[480px]" />
              </div>

              {/* Map Footer Bar */}
              <div className="mt-3 flex flex-wrap items-center justify-between text-[11px] text-slate-500 font-mono gap-2">
                <span>Projection: Natural Earth &bull; Accurate Boundaries &bull; Intensity Weights: Crit(5), High(4), Med(2), Low(1)</span>
                <span>Active Threat Nations: {data?.country_aggregates?.length || 0}</span>
              </div>
            </div>

            {/* Right 1 Col: Dynamic Country & Threat Intelligence Panel */}
            <div className="space-y-4">
              {/* Selected Country Intelligence Card */}
              {selectedCountry ? (
                <div className="p-5 rounded-2xl bg-[#090D16] border border-slate-800 shadow-xl space-y-4">
                  <div className="flex items-start justify-between pb-3 border-b border-slate-800">
                    <div>
                      <div className="text-[10px] text-slate-500 uppercase font-mono tracking-wider">
                        Inspected Nation
                      </div>
                      <h4 className="text-base font-bold text-white flex items-center gap-2 mt-0.5">
                        <span className="text-xl">🌍</span>
                        <span>{selectedCountry.country}</span>
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                          {selectedCountry.country_code || 'XX'}
                        </span>
                      </h4>
                    </div>

                    <div className="text-right">
                      <div className="text-[10px] text-slate-500 uppercase font-mono">Intensity Score</div>
                      <span className="inline-block mt-0.5 px-2.5 py-1 rounded-lg text-xs font-extrabold font-mono bg-gradient-to-r from-rose-500/20 to-pink-500/20 text-rose-400 border border-rose-500/40 shadow-[0_0_10px_rgba(244,63,94,0.2)]">
                        ⚡ {selectedCountry.intensity_score}
                      </span>
                    </div>
                  </div>

                  {/* 3 Metric Pills */}
                  <div className="grid grid-cols-3 gap-2">
                    <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800/80 text-center">
                      <div className="text-[10px] text-slate-500 uppercase font-mono">Events</div>
                      <div className="text-base font-bold font-mono text-cyan-400 mt-0.5">{selectedCountry.incident_count}</div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800/80 text-center">
                      <div className="text-[10px] text-slate-500 uppercase font-mono">Unique IPs</div>
                      <div className="text-base font-bold font-mono text-emerald-400 mt-0.5">{selectedCountry.unique_ips}</div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800/80 text-center">
                      <div className="text-[10px] text-slate-500 uppercase font-mono">Max Sev</div>
                      <div className="text-base font-bold font-mono text-rose-400 mt-0.5">{selectedCountry.max_severity || 'High'}</div>
                    </div>
                  </div>

                  {/* Severity Breakdown */}
                  <div className="space-y-1.5">
                    <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
                      <span>Severity Distribution</span>
                      <span className="text-[10px] text-slate-500 font-mono">Critical to Low</span>
                    </div>
                    <div className="grid grid-cols-4 gap-1.5 text-center font-mono text-xs">
                      <div className="p-1.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
                        <div className="text-[9px] uppercase">Crit</div>
                        <div className="font-bold">{selectedCountry.severities?.Critical || 0}</div>
                      </div>
                      <div className="p-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400">
                        <div className="text-[9px] uppercase">High</div>
                        <div className="font-bold">{selectedCountry.severities?.High || 0}</div>
                      </div>
                      <div className="p-1.5 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400">
                        <div className="text-[9px] uppercase">Med</div>
                        <div className="font-bold">{selectedCountry.severities?.Medium || 0}</div>
                      </div>
                      <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                        <div className="text-[9px] uppercase">Low</div>
                        <div className="font-bold">{selectedCountry.severities?.Low || 0}</div>
                      </div>
                    </div>
                  </div>

                  {/* Attack Categories */}
                  <div className="space-y-2">
                    <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                      Attack Categories
                    </div>
                    <div className="space-y-1.5">
                      {selectedCountry.categories && Object.keys(selectedCountry.categories).length > 0 ? (
                        Object.entries(selectedCountry.categories).map(([catName, count]) => (
                          <div key={catName} className="space-y-1">
                            <div className="flex items-center justify-between text-xs">
                              <span className="text-slate-300">{catName}</span>
                              <span className="font-mono text-cyan-400 font-bold">{count}</span>
                            </div>
                            <div className="w-full h-1.5 rounded-full bg-slate-950 overflow-hidden">
                              <div
                                className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-rose-500"
                                style={{
                                  width: `${Math.min(100, (count / (selectedCountry.incident_count || 1)) * 100)}%`,
                                }}
                              />
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="text-xs text-slate-500">No specific attack tags recorded.</div>
                      )}
                    </div>
                  </div>

                  {/* Recent Correlated Incidents */}
                  <div className="space-y-2 pt-2 border-t border-slate-800">
                    <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
                      <span>Recent Incidents ({selectedCountry.recent_incidents?.length || 0})</span>
                      <span className="text-[10px] text-cyan-400 font-mono">SQLite Stream</span>
                    </div>

                    <div className="space-y-1.5 max-h-[170px] overflow-y-auto pr-1">
                      {selectedCountry.recent_incidents && selectedCountry.recent_incidents.length > 0 ? (
                        selectedCountry.recent_incidents.map((inc, i) => (
                          <div
                            key={i}
                            className="p-2 rounded-lg bg-slate-950/90 border border-slate-800/80 flex items-center justify-between text-xs"
                          >
                            <div>
                              <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                                <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                                {inc.category}
                              </div>
                              <div className="text-[10px] font-mono text-cyan-400 mt-0.5">
                                {inc.source_ip}
                              </div>
                            </div>
                            <button
                              onClick={() => {
                                setLookupIp(inc.source_ip);
                                setActiveSubTab('lookup');
                                handleRunLookup(inc.source_ip);
                              }}
                              className="px-2 py-1 rounded text-[10px] font-mono font-semibold bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 transition-all cursor-pointer"
                            >
                              Inspect IP
                            </button>
                          </div>
                        ))
                      ) : (
                        <div className="text-xs text-slate-500 py-2">No recent incidents listed.</div>
                      )}
                    </div>
                  </div>

                  {/* Filter Action */}
                  <div className="pt-2 border-t border-slate-800">
                    <button
                      onClick={() => setCountryFilter(selectedCountry.country)}
                      className="w-full flex items-center justify-center gap-1.5 py-2 rounded-xl text-xs font-bold bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 transition-all cursor-pointer"
                    >
                      <Filter className="w-3.5 h-3.5" />
                      <span>Filter Map to {selectedCountry.country}</span>
                    </button>
                  </div>
                </div>
              ) : (
                <div className="p-8 rounded-2xl bg-[#090D16] border border-slate-800 text-center text-xs text-slate-500">
                  Click any colored nation on the Choropleth map to inspect detailed country threat metrics.
                </div>
              )}

              {/* Top Attacking Nations Leaderboard */}
              <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-lg">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 pb-2 border-b border-slate-800 flex items-center justify-between">
                  <span className="flex items-center gap-1.5">
                    <TrendingUp className="w-3.5 h-3.5 text-rose-400" />
                    Top Threat Origins (by Intensity)
                  </span>
                  <span className="text-[10px] font-mono text-slate-500">SQLite Ranking</span>
                </h4>

                <div className="mt-3 space-y-2.5">
                  {data?.country_aggregates && data.country_aggregates.length > 0 ? (
                    data.country_aggregates.slice(0, 5).map((c, i) => (
                      <div
                        key={c.country}
                        onClick={() => setSelectedCountry(c)}
                        className={`p-2 rounded-lg transition-all cursor-pointer ${
                          selectedCountry?.country === c.country
                            ? 'bg-cyan-500/10 border border-cyan-500/40'
                            : 'hover:bg-slate-800/50'
                        }`}
                      >
                        <div className="flex items-center justify-between text-xs font-medium">
                          <span className="text-white flex items-center gap-1.5">
                            <span className="text-slate-500 font-mono text-[10px]">#{i + 1}</span>
                            {c.country}
                          </span>
                          <span className="font-mono text-rose-400 font-bold">
                            ⚡ {c.intensity_score} pts
                          </span>
                        </div>
                        <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden mt-1">
                          <div
                            className="h-full rounded-full bg-gradient-to-r from-red-600 via-rose-500 to-pink-500"
                            style={{
                              width: `${Math.min(100, (c.intensity_score / (data.country_aggregates[0]?.intensity_score || 1)) * 100)}%`,
                            }}
                          />
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-4 text-xs text-slate-500">
                      No country telemetry aggregates detected.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Compact SQLite Threat Activity Timeline (Requirement 11) */}
          {data?.activity_timeline && data.activity_timeline.length > 0 && (
            <div className="p-4 rounded-xl bg-[#090D16] border border-slate-800 shadow-xl space-y-3">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4 text-cyan-400" />
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                    Real-Time SQLite Threat Activity Timeline ({timeWindow})
                  </h4>
                </div>
                <div className="flex items-center gap-3 text-[10px] font-mono text-slate-400">
                  <span className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-rose-500"></span> Critical (wt=5)
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-amber-500"></span> High (wt=4)
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-blue-500"></span> Medium (wt=2)
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-emerald-500"></span> Low (wt=1)
                  </span>
                </div>
              </div>

              {/* Distribution Buckets */}
              <div className="grid grid-cols-4 sm:grid-cols-8 md:grid-cols-12 gap-1.5 pt-1">
                {data.activity_timeline.slice(-12).map((pt, idx) => (
                  <div
                    key={idx}
                    className="p-2 rounded-lg bg-slate-950/80 border border-slate-800/80 flex flex-col items-center justify-between text-center min-h-[56px]"
                  >
                    <span className="text-[10px] text-slate-400 font-mono truncate w-full">{pt.label}</span>
                    <span className="text-sm font-bold font-mono text-rose-400 my-0.5">{pt.total_events}</span>
                    <div className="w-full flex h-1.5 rounded-full overflow-hidden bg-slate-800">
                      <div
                        style={{ width: `${(pt.critical / (pt.total_events || 1)) * 100}%` }}
                        className="bg-rose-500"
                        title={`Critical: ${pt.critical}`}
                      />
                      <div
                        style={{ width: `${(pt.high / (pt.total_events || 1)) * 100}%` }}
                        className="bg-amber-500"
                        title={`High: ${pt.high}`}
                      />
                      <div
                        style={{ width: `${(pt.medium / (pt.total_events || 1)) * 100}%` }}
                        className="bg-blue-500"
                        title={`Medium: ${pt.medium}`}
                      />
                      <div
                        style={{ width: `${(pt.low / (pt.total_events || 1)) * 100}%` }}
                        className="bg-emerald-500"
                        title={`Low: ${pt.low}`}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ===================================================================== */}
      {/* SUB-TAB 2: LOCAL NETWORK TOPOLOGY (PRIVATE IP SPACE) */}
      {/* ===================================================================== */}
      {activeSubTab === 'topology' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-purple-400" />
              Private Local Network Topology (RFC 1918 / Loopback)
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              SentinelAI explicitly separates unroutable internal addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and 127.0.0.1) from the public world map.
              These internal nodes represent LAN endpoints, testbed injectors, and host collectors.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {data?.local_network && data.local_network.length > 0 ? (
              data.local_network.map((host, idx) => (
                <div
                  key={`topo-${idx}`}
                  className="p-4 rounded-xl bg-[#0E1525] border border-slate-800 hover:border-purple-500/40 transition-all shadow-md space-y-2.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-sm text-purple-300">{host.ip}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/40">
                      {host.rfc_type || 'RFC 1918 Private'}
                    </span>
                  </div>

                  <div className="text-xs text-slate-400">
                    <div>
                      Packets / Volume:{' '}
                      <span className="font-mono text-white">{host.packet_count || 1} flows</span>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {host.categories?.map((c) => (
                        <span
                          key={c}
                          className="px-1.5 py-0.5 rounded text-[9px] bg-slate-800 text-slate-300"
                        >
                          {c}
                        </span>
                      ))}
                    </div>
                  </div>

                  <button
                    onClick={() => {
                      setLookupIp(host.ip);
                      setActiveSubTab('lookup');
                      handleRunLookup(host.ip);
                    }}
                    className="w-full text-center py-1 rounded text-[11px] font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer"
                  >
                    Inspect Provenance &rarr;
                  </button>
                </div>
              ))
            ) : (
              <div className="col-span-3 text-center py-10 text-xs text-slate-500">
                No local network addresses currently buffered.
              </div>
            )}
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* SUB-TAB 3: SOURCE IP INTELLIGENCE INSPECTOR */}
      {/* ===================================================================== */}
      {activeSubTab === 'lookup' && (
        <div className="space-y-5">
          {/* IP Input Form */}
          <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-cyan-400" />
              Deep Source IP Intelligence & Provenance Inspector
            </h3>
            <p className="text-xs text-slate-400">
              Query any IPv4 address against the loaded MaxMind GeoLite2 City binary (.mmdb) and cross-reference with stored SQLite network logs and incidents.
            </p>

            <div className="flex flex-col sm:flex-row items-center gap-3 pt-2">
              <div className="relative flex-1 w-full">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={lookupIp}
                  onChange={(e) => setLookupIp(e.target.value)}
                  placeholder="Enter IP address (e.g. 128.30.52.100, 198.51.100.23, 10.0.0.15)"
                  className="w-full pl-9 pr-4 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <button
                onClick={() => handleRunLookup()}
                disabled={lookupLoading}
                className="w-full sm:w-auto px-5 py-2 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-colors flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 cursor-pointer"
              >
                {lookupLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
                <span>Perform GeoIP Inspection</span>
              </button>
            </div>

            {/* Quick-test Presets */}
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 pt-1">
              <span>Quick Test Targets:</span>
              <button
                onClick={() => {
                  setLookupIp('128.30.52.100');
                  handleRunLookup('128.30.52.100');
                }}
                className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-[11px] hover:bg-slate-700 cursor-pointer"
              >
                128.30.52.100 (MIT, US)
              </button>
              <button
                onClick={() => {
                  setLookupIp('198.51.100.23');
                  handleRunLookup('198.51.100.23');
                }}
                className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-[11px] hover:bg-slate-700 cursor-pointer"
              >
                198.51.100.23 (Zurich, CH)
              </button>
              <button
                onClick={() => {
                  setLookupIp('198.51.100.99');
                  handleRunLookup('198.51.100.99');
                }}
                className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-[11px] hover:bg-slate-700 cursor-pointer"
              >
                198.51.100.99 (Frankfurt, DE)
              </button>
              <button
                onClick={() => {
                  setLookupIp('192.168.1.15');
                  handleRunLookup('192.168.1.15');
                }}
                className="px-2 py-0.5 rounded bg-slate-800 text-purple-300 font-mono text-[11px] hover:bg-slate-700 cursor-pointer"
              >
                192.168.1.15 (RFC 1918 Private)
              </button>
            </div>
          </div>

          {/* Lookup Result Card */}
          {lookupError && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
              Error during lookup: {lookupError}
            </div>
          )}

          {lookupResult && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              {/* Left Box: GeoIP Intelligence Details */}
              <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4 shadow-xl">
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase font-mono">Verified Address</span>
                    <h4 className="text-base font-bold text-cyan-400 font-mono">{lookupResult.ip}</h4>
                  </div>
                  <span
                    className={`px-2.5 py-1 rounded text-xs font-bold font-mono ${
                      lookupResult.intelligence.is_public
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                    }`}
                  >
                    {lookupResult.intelligence.is_public ? 'PUBLIC ROUTABLE' : 'PRIVATE / NON-ROUTABLE'}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Country / Nation</span>
                    <span className="text-white font-semibold">
                      {lookupResult.intelligence.country || 'Unknown'} ({lookupResult.intelligence.country_code || 'XX'})
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">City / Region</span>
                    <span className="text-white font-semibold">
                      {lookupResult.intelligence.city || 'Unknown'}, {lookupResult.intelligence.region || '—'}
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Latitude / Longitude</span>
                    <span className="text-slate-300">
                      {lookupResult.intelligence.latitude !== undefined && lookupResult.intelligence.latitude !== null
                        ? `${lookupResult.intelligence.latitude.toFixed(4)}, ${lookupResult.intelligence.longitude?.toFixed(4)}`
                        : 'Coordinates Not Applicable'}
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Accuracy Radius</span>
                    <span className="text-slate-300">
                      {lookupResult.intelligence.accuracy_km ? `±${lookupResult.intelligence.accuracy_km} km` : '—'}
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Autonomous System</span>
                    <span className="text-slate-300">{lookupResult.intelligence.asn || 'AS Unknown'}</span>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Organization / ISP</span>
                    <span className="text-slate-300 truncate block">{lookupResult.intelligence.org || 'Unspecified'}</span>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Lookup Status</span>
                    <span className="text-cyan-400">{lookupResult.intelligence.status}</span>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">RFC Standard</span>
                    <span className="text-purple-300">{lookupResult.intelligence.rfc_designation || 'RFC 791 Public Space'}</span>
                  </div>
                </div>
              </div>

              {/* Right Box: Stored SQLite Telemetry History */}
              <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4 shadow-xl">
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <Database className="w-4 h-4 text-emerald-400" />
                    Stored SQLite Telemetry & Incidents
                  </h4>
                  <span className="text-xs font-mono text-slate-400">
                    {lookupResult.recent_flows_count} flows observed
                  </span>
                </div>

                <div className="space-y-3">
                  <div>
                    <span className="text-[10px] uppercase font-mono text-slate-500">Correlated Security Incidents</span>
                    {lookupResult.incidents && lookupResult.incidents.length > 0 ? (
                      <div className="space-y-1.5 mt-1">
                        {lookupResult.incidents.map((inc, i) => (
                          <div
                            key={i}
                            className="p-2 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs"
                          >
                            <span className="font-semibold text-white">{inc.category || 'Threat Alert'}</span>
                            <span className="text-rose-400 font-mono font-bold">{inc.severity || 'High'}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-xs text-slate-500 mt-1">No correlated security incidents from this host.</div>
                    )}
                  </div>

                  <div className="pt-2 border-t border-slate-800">
                    <span className="text-[10px] uppercase font-mono text-slate-500">Recent Network Logs</span>
                    {lookupResult.recent_flows && lookupResult.recent_flows.length > 0 ? (
                      <div className="space-y-1 mt-1 font-mono text-[11px]">
                        {lookupResult.recent_flows.map((flow, i) => (
                          <div
                            key={i}
                            className="p-1.5 rounded bg-slate-950/60 border border-slate-800/80 flex items-center justify-between text-slate-300"
                          >
                            <span>Port {flow.destination_port || '—'} ({flow.protocol || 'TCP'})</span>
                            <span className="text-slate-500 text-[10px]">{flow.timestamp || 'Recent'}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-xs text-slate-500 mt-1">No recent raw flows logged.</div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
export default ThreatIntelligencePage;
