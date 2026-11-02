import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Globe,
  ShieldAlert,
  Search,
  Filter,
  MapPin,
  Server,
  Activity,
  AlertTriangle,
  Database,
  Radio,
  Clock,
  Crosshair,
  RefreshCw,
  TrendingUp,
  Zap,
  Sparkles,
  Play,
  Pause,
  X,
  Shield,
  ShieldCheck,
  ArrowRight,
  Target,
  Send,
  CheckCircle2,
  ExternalLink,
} from 'lucide-react';
import { api } from '../services/api';
import {
  ThreatMapData,
  ThreatMarker,
  CountryAggregate,
  LocalNetworkHost,
  IpIntelligence,
  LiveThreatEvent,
  AttackTrajectory,
  CopilotExplanation,
} from '../types';
import Plotly from 'plotly.js-dist-min';

// Generates smooth parabolic curved arc points between source and target for attack trajectory visualization
function generateArcPoints(
  srcLat: number,
  srcLon: number,
  dstLat: number,
  dstLon: number,
  numPoints: number = 20
): { lats: number[]; lons: number[] } {
  const lats: number[] = [];
  const lons: number[] = [];

  const dLat = dstLat - srcLat;
  const dLon = dstLon - srcLon;
  const dist = Math.sqrt(dLat * dLat + dLon * dLon);

  // Parabolic bow factor proportional to geographic distance
  // If dist is small (e.g. laptop in Gujarat to Vadodara), bow both lat and lon so it creates a visible curved arc loop
  let bowLat = Math.min(24, Math.max(7, dist * 0.25));
  let bowLon = 0;
  if (dist < 4.0) {
    bowLat = 7.0;
    bowLon = 6.0; // expand horizontally as well for local attacks so it loops visibly
  }

  for (let i = 0; i <= numPoints; i++) {
    const t = i / numPoints;
    let lat = srcLat + t * dLat;
    let lon = srcLon + t * dLon;

    // Curved apex
    const arcHeight = Math.sin(t * Math.PI);
    lat += arcHeight * bowLat;
    lon += arcHeight * bowLon;

    lats.push(lat);
    lons.push(lon);
  }
  return { lats, lons };
}

export const ThreatIntelligencePage: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'geo' | 'topology' | 'lookup'>('geo');
  const [data, setData] = useState<ThreatMapData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Live real-time stream status & pause toggle
  const [isLiveStreaming, setIsLiveStreaming] = useState<boolean>(true);
  const [lastStreamUpdate, setLastStreamUpdate] = useState<Date>(new Date());
  const [measuredDelay, setMeasuredDelay] = useState<number>(24);

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
  const isMapInitialized = useRef<boolean>(false);

  // IP Lookup Inspector State
  const [lookupIp, setLookupIp] = useState<string>('103.235.91.132');
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

  // Test Attack Generator Modal State
  const [showSimulateModal, setShowSimulateModal] = useState<boolean>(false);
  const [simIp, setSimIp] = useState<string>('103.235.91.132'); // Default to user's public IP from Gujarat
  const [simTargetPort, setSimTargetPort] = useState<number>(22);
  const [simAttackType, setSimAttackType] = useState<string>('Brute Force');
  const [simSeverity, setSimSeverity] = useState<string>('High');
  const [simEventCount, setSimEventCount] = useState<number>(3);
  const [simulating, setSimulating] = useState<boolean>(false);
  const [simFeedback, setSimFeedback] = useState<{ type: 'success' | 'error'; message: string; details?: any } | null>(null);

  // Gemini AI Copilot Incident Investigation Modal State
  const [copilotModalOpen, setCopilotModalOpen] = useState<boolean>(false);
  const [copilotLoading, setCopilotLoading] = useState<boolean>(false);
  const [copilotData, setCopilotData] = useState<{
    incidentId: string;
    incident: any;
    explanation: CopilotExplanation;
    safe_recommendations?: any;
  } | null>(null);
  const [copilotError, setCopilotError] = useState<string | null>(null);

  // Fetch threat map data from backend
  const fetchData = useCallback(async (isBackground: boolean = false) => {
    try {
      if (!isBackground) setLoading(true);
      setError(null);
      const res = await api.getThreatMap({
        severity: severityFilter,
        category: categoryFilter,
        country: countryFilter,
        timeRange: timeWindow,
      });
      setData(res);
      setLastStreamUpdate(new Date());
      if (res.latest_ingestion_delay_ms !== undefined) {
        setMeasuredDelay(res.latest_ingestion_delay_ms);
      }

      if (res.country_aggregates && res.country_aggregates.length > 0) {
        setSelectedCountry((prev) => {
          if (!prev) return res.country_aggregates[0];
          const exists = res.country_aggregates.find(
            (c) => c.country.toLowerCase() === prev.country.toLowerCase()
          );
          return exists || res.country_aggregates[0];
        });
      }

      if (res.markers && res.markers.length > 0) {
        setSelectedMarker((prev) => {
          if (!prev) return res.markers[0];
          const exists = res.markers.find(
            (m) => m.city.toLowerCase() === prev.city.toLowerCase() && m.country === prev.country
          );
          return exists || res.markers[0];
        });
      }
    } catch (e: any) {
      console.error('Failed to load threat map data', e);
      if (!isBackground) {
        setError(e.message || 'Error fetching threat map data');
      }
    } finally {
      if (!isBackground) setLoading(false);
    }
  }, [severityFilter, categoryFilter, countryFilter, timeWindow]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Real-time SSE & continuous 2s auto-refresh loop
  useEffect(() => {
    if (!isLiveStreaming) return;

    // Active polling interval: forces map, ticker, and counters to refresh continuously every 2000ms
    const pollInterval = setInterval(() => {
      fetchData(true);
    }, 2000);

    let eventSource: EventSource | null = null;
    try {
      // Connect to FastAPI SSE stream for instant push
      eventSource = new EventSource('/api/threat-map/stream');

      eventSource.onmessage = (event) => {
        try {
          const streamData = JSON.parse(event.data);
          if (streamData && streamData.status === 'success') {
            setData((prev) => ({
              ...prev,
              ...streamData,
              statistics: streamData.statistics || prev?.statistics,
            }));
            setLastStreamUpdate(new Date());
            if (streamData.latest_ingestion_delay_ms) {
              setMeasuredDelay(streamData.latest_ingestion_delay_ms);
            }
          }
        } catch (err) {
          // ignore
        }
      };
    } catch (err) {
      // ignore
    }

    return () => {
      clearInterval(pollInterval);
      if (eventSource) eventSource.close();
    };
  }, [isLiveStreaming, fetchData]);

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

  const handleSimulateAttack = async () => {
    try {
      setSimulating(true);
      setSimFeedback(null);
      const res: any = await api.simulateAttack({
        source_ip: simIp.trim(),
        target_port: simTargetPort,
        attack_type: simAttackType,
        severity: simSeverity,
        event_count: simEventCount,
      });

      setSimFeedback({
        type: 'success',
        message: res.message || 'Authorized test attack injected successfully.',
        details: res,
      });

      // Immediately fetch fresh threat map data
      const updatedMap = await api.getThreatMap({
        severity: severityFilter,
        category: categoryFilter,
        country: countryFilter,
        timeRange: timeWindow,
      });
      setData(updatedMap);
      setLastStreamUpdate(new Date());

      // AUTO-FOCUS & AUTO-SELECT the new attack source location on the map!
      if (res.is_public && updatedMap.markers && updatedMap.markers.length > 0) {
        const hitMarker = updatedMap.markers.find(
          (m) =>
            m.source_ips?.includes(res.source_ip) ||
            (m.city && res.city && m.city.toLowerCase() === res.city.toLowerCase())
        );
        if (hitMarker) {
          setSelectedMarker(hitMarker);
        } else {
          setSelectedMarker(updatedMap.markers[0]);
        }

        if (res.country && updatedMap.country_aggregates) {
          const hitCountry = updatedMap.country_aggregates.find(
            (c) => c.country.toLowerCase() === (res.country || '').toLowerCase()
          );
          if (hitCountry) {
            setSelectedCountry(hitCountry);
          }
        }
      } else if (!res.is_public) {
        // If private IP (e.g. 10.x.x.x, 192.168.x.x, 127.0.0.1) switch to Local Network tab
        setActiveSubTab('topology');
      }

      // Automatically close the modal after 1.4 seconds so the user sees the confirmation and then the map
      setTimeout(() => {
        setShowSimulateModal(false);
      }, 1400);
    } catch (e: any) {
      setSimFeedback({
        type: 'error',
        message: e.message || 'Failed to simulate attack event',
      });
    } finally {
      setSimulating(false);
    }
  };

  const handleOpenGeminiInvestigation = async (incidentId?: string) => {
    // If no specific incident id provided, pick primary or top incident
    const incId = incidentId || selectedMarker?.primary_incident_id || 'INC-2026-001';
    setCopilotModalOpen(true);
    setCopilotLoading(true);
    setCopilotError(null);

    try {
      const res = await api.getCopilotExplanation(incId);
      setCopilotData({
        incidentId: incId,
        incident: res.incident,
        explanation: res.explanation,
        safe_recommendations: res.safe_recommendations,
      });
    } catch (e: any) {
      setCopilotError(e.message || 'Failed to load Gemini AI copilot explanation.');
    } finally {
      setCopilotLoading(false);
    }
  };

  const getSeverityRingColor = (sev?: string) => {
    switch ((sev || 'medium').toLowerCase()) {
      case 'critical':
        return '#FF4D6D'; // Neon pink
      case 'high':
        return '#EF233C'; // Bright red
      case 'medium':
        return '#F59E0B'; // Amber
      case 'low':
        return '#10B981'; // Emerald
      default:
        return '#06B6D4';
    }
  };

  const getSeverityHaloColor = (sev?: string) => {
    switch ((sev || 'medium').toLowerCase()) {
      case 'critical':
        return 'rgba(255, 77, 109, 0.28)';
      case 'high':
        return 'rgba(239, 35, 60, 0.25)';
      case 'medium':
        return 'rgba(245, 158, 11, 0.22)';
      case 'low':
        return 'rgba(16, 185, 129, 0.20)';
      default:
        return 'rgba(6, 182, 212, 0.22)';
    }
  };

  const getSeverityCoreColor = (sev?: string) => {
    switch ((sev || 'medium').toLowerCase()) {
      case 'critical':
        return '#FF4D6D';
      case 'high':
        return '#EF233C';
      case 'medium':
        return '#F59E0B';
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

  // =========================================================================
  // RENDER INTERACTIVE PLOTLY WAR-ROOM HEAT MAP
  // =========================================================================
  useEffect(() => {
    if (activeSubTab !== 'geo' || !mapContainerRef.current) return;

    const countries = data?.country_aggregates || [];
    const markers = data?.markers || [];
    const trajectories = data?.attack_trajectories || [];

    // Red/pink threat intensity gradient matching reference screenshots:
    // Low: Dark red (#38040E) -> Medium: (#A8132B) -> High: (#EF233C) -> Critical: Vivid pink/red (#FF4D6D)
    const redPinkColorscale: [number, string][] = [
      [0.0, '#38040E'],
      [0.25, '#670A1A'],
      [0.5, '#A8132B'],
      [0.75, '#EF233C'],
      [1.0, '#FF4D6D'],
    ];

    const traces: any[] = [];

    // 1. BASE LAYER: Interactive Country Threat Intensity Choropleth
    if (countries.length > 0) {
      const choroplethTrace: any = {
        type: 'choropleth',
        locationmode: 'country names',
        locations: countries.map((c) => c.country),
        z: countries.map((c) => Math.max(1, c.intensity_score)),
        text: countries.map((c) => c.country),
        customdata: countries.map((c) => ({
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
          bgcolor: 'rgba(11, 19, 43, 0.85)',
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

    // 2. LAYER 1: Sentinel SOC Target Anchor (Vadodara Gateway)
    const socTargetTrace: any = {
      type: 'scattergeo',
      lat: [22.3072],
      lon: [73.1812],
      mode: 'markers+text',
      text: ['🛡️ Sentinel SOC'],
      textposition: 'bottom center',
      textfont: {
        color: '#38BDF8',
        size: 9,
        family: 'Inter, sans-serif',
      },
      marker: {
        size: 11,
        symbol: 'diamond',
        color: '#06B6D4',
        line: {
          color: '#FFFFFF',
          width: 1.5,
        },
      },
      hovertemplate:
        '<span style="font-family:Inter; font-size:12px;">' +
        '<b style="font-size:13px; color:#38BDF8;">🛡️ SentinelAI SOC & Edge Collector</b><br>' +
        'Location: <b>Vadodara, Gujarat (22.3072° N, 73.1812° E)</b><br>' +
        'Status: <b style="color:#10B981;">Active Ingestion & Honeypot Sensor</b><br>' +
        'Monitored Ports: <b>22, 80, 443, 8000</b>' +
        '</span><extra></extra>',
      showlegend: false,
    };
    traces.push(socTargetTrace);

    // 3. LAYER 2: Curved Attack Trajectory Arcs / Vectors
    if (trajectories.length > 0) {
      const arcLats: (number | null)[] = [];
      const arcLons: (number | null)[] = [];
      const arcTexts: string[] = [];

      trajectories.forEach((traj) => {
        const arc = generateArcPoints(traj.source_lat, traj.source_lon, traj.target_lat, traj.target_lon);
        arcLats.push(...arc.lats, null);
        arcLons.push(...arc.lons, null);
        arc.lats.forEach(() => {
          arcTexts.push(`⚡ Attack Vector: ${traj.source_ip} ➔ ${traj.target_ip} (${traj.category})`);
        });
        arcTexts.push('');
      });

      const trajectoryTrace: any = {
        type: 'scattergeo',
        lat: arcLats,
        lon: arcLons,
        mode: 'lines',
        line: {
          color: '#FF4D6D',
          width: 2.0,
        },
        opacity: 0.8,
        hoverinfo: 'text',
        text: arcTexts,
        showlegend: false,
      };
      traces.push(trajectoryTrace);
    }

    // 4. LAYER 3: Diffuse Outer Heat Concentration Halo (Large Translucent Glow)
    if (markers.length > 0) {
      const haloTrace: any = {
        type: 'scattergeo',
        lat: markers.map((m) => m.latitude),
        lon: markers.map((m) => m.longitude),
        mode: 'markers',
        hoverinfo: 'skip',
        marker: {
          size: markers.map((m) => Math.min(68, Math.max(28, (m.heat_intensity || 5) * 3.5 + 20))),
          color: markers.map((m) => getSeverityHaloColor(m.severity || m.max_severity)),
          symbol: 'circle',
          line: { width: 0 },
        },
        showlegend: false,
      };
      traces.push(haloTrace);

      // 5. LAYER 4: Concentric Shockwave Pulse Rings (Hollow Concentric Circle)
      const shockwaveTrace: any = {
        type: 'scattergeo',
        lat: markers.map((m) => m.latitude),
        lon: markers.map((m) => m.longitude),
        mode: 'markers',
        hoverinfo: 'skip',
        marker: {
          size: markers.map((m) => Math.min(42, Math.max(18, (m.heat_intensity || 5) * 2.2 + 14))),
          color: 'rgba(0,0,0,0)',
          line: {
            color: markers.map((m) => getSeverityRingColor(m.severity || m.max_severity)),
            width: 2.2,
          },
          symbol: 'circle',
        },
        showlegend: false,
      };
      traces.push(shockwaveTrace);

      // 6. LAYER 5: High-Intensity Hotspot Core (Grounded White-Pink Neon Center on top layer)
      const coreTrace: any = {
        type: 'scattergeo',
        lat: markers.map((m) => m.latitude),
        lon: markers.map((m) => m.longitude),
        text: markers.map((m) => `${m.city || 'Origin'}, ${m.region ? `${m.region}, ` : ''}${m.country || ''}`),
        customdata: markers.map((m) => ({
          city: m.city || 'Origin',
          region_part: m.region ? `${m.region}, ` : '',
          country: m.country || '',
          source_ips: (m.source_ips || []).join(', '),
          heat_intensity: m.heat_intensity || 5,
          severity: m.severity || m.max_severity || 'Medium',
          categories: (m.categories || []).join(', '),
          accuracy_km: m.accuracy_km || m.accuracy_radius || 20,
          last_seen: m.last_seen || 'Live',
          marker_raw: m,
        })),
        mode: 'markers',
        marker: {
          size: markers.map((m) => Math.min(18, Math.max(9, Math.sqrt((m.heat_intensity || 5) * 4) + 6))),
          color: markers.map((m) => getSeverityCoreColor(m.severity || m.max_severity)),
          line: {
            color: '#FFFFFF',
            width: 2,
          },
          opacity: 1.0,
        },
        hovertemplate:
          '<span style="font-family:Inter; font-size:12px;">' +
          '<b style="font-size:14px; color:#FFFFFF;">📍 %{customdata.city}, %{customdata.region_part}%{customdata.country}</b><br>' +
          '🌐 Source IP(s): <b>%{customdata.source_ips}</b><br>' +
          '⚡ Heat Intensity: <b>%{customdata.heat_intensity}</b><br>' +
          '⚠️ Severity: <b>%{customdata.severity}</b><br>' +
          '🎯 Attack Categories: <b>%{customdata.categories}</b><br>' +
          '📏 Accuracy Radius: <b>±%{customdata.accuracy_km} km</b><br>' +
          '🕒 Last Seen: <b>%{customdata.last_seen}</b>' +
          '</span><extra></extra>',
        showlegend: false,
      };
      traces.push(coreTrace);
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
        landcolor: '#0B132B', // Dark navy land for countries without suspicious events
        showocean: true,
        oceancolor: '#070A11', // Deep dark ocean
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
      height: 520,
      showlegend: false,
    };

    const config: any = {
      responsive: true,
      displayModeBar: false,
    };

    // Use Plotly.react for seamless in-place updates without destroying state or resetting zoom/pan
    if (isMapInitialized.current) {
      Plotly.react(mapContainerRef.current, traces, layout, config);
    } else {
      Plotly.newPlot(mapContainerRef.current, traces, layout, config).then(() => {
        isMapInitialized.current = true;
        const plotEl = mapContainerRef.current as any;
        if (!plotEl) return;

        plotEl.removeAllListeners?.('plotly_click');
        plotEl.on('plotly_click', (eventData: any) => {
          if (!eventData || !eventData.points || eventData.points.length === 0) return;
          const pt = eventData.points[0];
          if (pt.data.type === 'choropleth') {
            const clickedCountryName = pt.location;
            const match = (data?.country_aggregates || []).find(
              (c) => c.country.toLowerCase() === String(clickedCountryName).toLowerCase()
            );
            if (match) setSelectedCountry(match);
          } else if (pt.data.type === 'scattergeo' && pt.customdata) {
            const rawMarker = pt.customdata.marker_raw || pt.customdata;
            setSelectedMarker(rawMarker);
            const targetCountry = rawMarker.country || pt.customdata.country;
            const match = (data?.country_aggregates || []).find(
              (c) => c.country.toLowerCase() === String(targetCountry).toLowerCase()
            );
            if (match) setSelectedCountry(match);
          }
        });
      });
    }

    const handleResize = () => {
      if (mapContainerRef.current) {
        Plotly.Plots.resize(mapContainerRef.current);
      }
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
    };
  }, [data, activeSubTab]);

  return (
    <div className="space-y-6">
      {/* Page Header with Real-Time Badges */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between p-5 rounded-2xl bg-gradient-to-r from-slate-900/90 via-[#0D1526]/80 to-slate-900/90 border border-slate-800 shadow-xl gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-rose-500/20 border border-rose-500/40 flex items-center justify-center text-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.3)]">
              <Globe className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h1 className="text-lg font-bold text-white tracking-wide">
                  Real-Time Attack Origin Tracking & Threat Heat Map
                </h1>
                <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                  LIVE STREAM ACTIVE
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5 flex items-center gap-2">
                <span>MaxMind GeoLite2 City Geolocation</span>
                <span>&bull;</span>
                <span>Concentric Shockwave Pulses</span>
                <span>&bull;</span>
                <span>Dynamic Attack Trajectory Vectors</span>
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls & Sub-tab navigation */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Measured Ingestion Latency Badge */}
          <div
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-950/80 border border-slate-800 text-[11px] font-mono text-cyan-300"
            title="Measured packet ingestion-to-dashboard delay"
          >
            <Activity className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>Ingestion Delay:</span>
            <strong className="text-white font-bold">{measuredDelay} ms</strong>
          </div>

          {/* Test Attack Traffic Drawer Trigger */}
          <button
            onClick={() => {
              setShowSimulateModal(true);
              setSimFeedback(null);
            }}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-bold bg-gradient-to-r from-rose-500 to-pink-500 hover:from-rose-600 hover:to-pink-600 text-white shadow-lg shadow-rose-500/20 transition-all cursor-pointer"
          >
            <Zap className="w-3.5 h-3.5 fill-current" />
            <span>Generate Test Attack Traffic</span>
          </button>

          {/* Stream Pause / Play Toggle */}
          <button
            onClick={() => setIsLiveStreaming(!isLiveStreaming)}
            className={`p-2 rounded-xl text-xs border transition-colors cursor-pointer ${
              isLiveStreaming
                ? 'bg-slate-900 border-slate-700 text-slate-300 hover:text-white'
                : 'bg-amber-500/20 border-amber-500/40 text-amber-300'
            }`}
            title={isLiveStreaming ? 'Pause Real-Time Stream' : 'Resume Real-Time Stream'}
          >
            {isLiveStreaming ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
          </button>

          {/* Sub-tab navigation */}
          <div className="flex items-center gap-1 p-1 rounded-xl bg-slate-950/80 border border-slate-800">
            <button
              onClick={() => setActiveSubTab('geo')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                activeSubTab === 'geo'
                  ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>Attack Map</span>
            </button>

            <button
              onClick={() => setActiveSubTab('topology')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                activeSubTab === 'topology'
                  ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <Server className="w-3.5 h-3.5" />
              <span>Local Network ({data?.local_network?.length || 0})</span>
            </button>

            <button
              onClick={() => {
                setActiveSubTab('lookup');
                if (!lookupResult) handleRunLookup();
              }}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                activeSubTab === 'lookup'
                  ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <Crosshair className="w-3.5 h-3.5" />
              <span>IP Inspector</span>
            </button>
          </div>
        </div>
      </div>

      {/* Real-World Geolocation Notice & Disclaimer */}
      <div className="flex items-start gap-3 p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-200 text-xs">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div>
            <strong className="font-semibold text-amber-300">Geographic Telemetry Specification:</strong> IP geolocation is approximate (confidence radius shown per host, e.g. ±20km for Gujarat/Vadodara district). It identifies the network routing egress point, not a physical person. RFC 1918 private subnets (10.x.x.x, 192.168.x.x, 172.16.x.x) and loopback (127.0.0.1) are segregated into the Local Network tab.
          </div>
        </div>
      </div>

      {/* 5 Required Key KPI Statistics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="p-4 rounded-xl bg-[#0F172A]/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Geolocated Origins</span>
            <MapPin className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-1.5 font-mono">{stats.total_geolocated_sources}</div>
          <div className="text-[10px] text-rose-400 mt-1 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse" />
            Active Shockwave Nodes
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A]/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Origin Nations</span>
            <Globe className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-1.5 font-mono">{stats.countries_detected}</div>
          <div className="text-[10px] text-emerald-400 mt-1">Choropleth Threat Regions</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A]/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Suspicious Probes</span>
            <Activity className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-1.5 font-mono">{stats.total_suspicious_events}</div>
          <div className="text-[10px] text-slate-400 mt-1">SQLite verified records</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A]/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Private LAN Subnets</span>
            <Server className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-1.5 font-mono">{stats.unlocated_source_ips}</div>
          <div className="text-[10px] text-purple-400 mt-1">RFC 1918 Segregated</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A]/90 border border-slate-800/80 shadow-md">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Critical & High</span>
            <ShieldAlert className="w-3.5 h-3.5 text-pink-400" />
          </div>
          <div className="text-2xl font-bold text-pink-400 mt-1.5 font-mono">{stats.high_critical_events}</div>
          <div className="text-[10px] text-pink-400 mt-1">Active shockwave priority</div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* SUB-TAB 1: GEOGRAPHIC WAR-ROOM THREAT MAP */}
      {/* ===================================================================== */}
      {activeSubTab === 'geo' && (
        <div className="space-y-6">
          {/* Filter Controls Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-slate-900/80 border border-slate-800">
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Filter className="w-3.5 h-3.5 text-cyan-400" /> Telemetry Scope:
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
                <option value="Brute Force">Brute Force</option>
                <option value="Port Scan">Port Scan</option>
                <option value="DDoS Surge">DDoS Surge</option>
                <option value="Web Reconnaissance">Web Reconnaissance</option>
                <option value="Data Exfiltration">Data Exfiltration</option>
              </select>
            </div>

            <button
              onClick={() => fetchData()}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
              <span>Refresh Map</span>
            </button>
          </div>

          {/* Map & Live Source Intelligence Panel */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Left 2 Cols: Plotly World Choropleth + Shockwave Heat Spots + Trajectories */}
            <div className="lg:col-span-2 p-5 rounded-2xl bg-[#090D16] border border-slate-800 shadow-2xl relative overflow-hidden flex flex-col justify-between">
              {/* Map Canvas Header */}
              <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 mb-2">
                <div className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping" />
                  <h3 className="text-sm font-bold text-white tracking-wide">
                    Global Attack Origin Heat Map & Attack Trajectory Vectors
                  </h3>
                </div>
                <div className="flex items-center gap-3 text-[11px] text-slate-400 font-mono">
                  <span className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-sm bg-[#38040E]" /> Low
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-sm bg-[#A8132B]" /> Medium
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-sm bg-[#EF233C]" /> High
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-sm bg-[#FF4D6D]" /> Critical
                  </span>
                </div>
              </div>

              {/* Plotly Interactive Canvas Container */}
              <div className="relative w-full min-h-[520px] bg-[#070A11] rounded-xl border border-slate-800/50 overflow-hidden flex items-center justify-center">
                {loading && (
                  <div className="absolute inset-0 bg-[#070A11]/70 backdrop-blur-sm z-10 flex items-center justify-center gap-3 text-cyan-400 text-sm font-mono">
                    <RefreshCw className="w-5 h-5 animate-spin" />
                    <span>Synchronizing Live Shockwaves...</span>
                  </div>
                )}
                <div ref={mapContainerRef} className="w-full h-[520px]" />
              </div>

              {/* Map Footer Bar with SOC Target Legend */}
              <div className="mt-3 flex flex-wrap items-center justify-between text-[11px] text-slate-500 font-mono gap-2 pt-2 border-t border-slate-800/60">
                <div className="flex items-center gap-4">
                  <span className="flex items-center gap-1 text-cyan-400">
                    <span className="w-2 h-2 rounded-none rotate-45 bg-cyan-400" /> Target Asset: Sentinel SOC Vadodara (22.30° N, 73.18° E)
                  </span>
                  <span className="flex items-center gap-1 text-rose-400">
                    <span className="w-3 h-0.5 bg-rose-500" /> Trajectory Arc
                  </span>
                </div>
                <span>Active Heat Concentrations: {data?.markers?.length || 0}</span>
              </div>
            </div>

            {/* Right 1 Col: Live Source Intelligence & Geolocation Drawer */}
            <div className="space-y-4">
              {/* Selected Source Marker Card */}
              {selectedMarker ? (
                <div className="p-5 rounded-2xl bg-[#090D16] border border-slate-800 shadow-xl space-y-4">
                  <div className="flex items-start justify-between pb-3 border-b border-slate-800">
                    <div>
                      <div className="text-[10px] text-slate-500 uppercase font-mono tracking-wider flex items-center gap-1">
                        <MapPin className="w-3 h-3 text-rose-400" />
                        Selected Threat Source
                      </div>
                      <h4 className="text-base font-bold text-white flex items-center gap-2 mt-0.5">
                        <span>{selectedMarker.city || 'Origin'}</span>
                        <span className="text-slate-400 font-normal text-xs">{selectedMarker.country}</span>
                      </h4>
                      <div className="text-xs font-mono text-cyan-400 mt-0.5">
                        {selectedMarker.source_ips?.join(', ')}
                      </div>
                    </div>

                    <div className="text-right">
                      <div className="text-[10px] text-slate-500 uppercase font-mono">Heat Intensity</div>
                      <span className="inline-block mt-0.5 px-2.5 py-1 rounded-lg text-xs font-extrabold font-mono bg-gradient-to-r from-rose-500/20 to-pink-500/20 text-rose-400 border border-rose-500/40 shadow-[0_0_10px_rgba(244,63,94,0.2)]">
                        ⚡ {selectedMarker.heat_intensity} pts
                      </span>
                    </div>
                  </div>

                  {/* IPS Active Containment Status */}
                  {selectedMarker.is_blocked ? (
                    <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2 text-emerald-400 font-bold">
                        <ShieldCheck className="w-4 h-4 text-emerald-400" />
                        <span>Actively Contained by Windows Firewall</span>
                      </div>
                      <a
                        href="/intrusion-prevention"
                        className="text-[11px] text-cyan-400 hover:text-white underline font-mono flex items-center gap-1"
                      >
                        Inspect in IPS ➔
                      </a>
                    </div>
                  ) : (
                    <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs text-slate-400">
                      <div className="flex items-center gap-2">
                        <Radio className="w-3.5 h-3.5 text-amber-400" />
                        <span>Firewall State: Monitoring</span>
                      </div>
                      <a
                        href="/intrusion-prevention"
                        className="text-[11px] text-slate-400 hover:text-cyan-400 font-mono"
                      >
                        IPS Controls ➔
                      </a>
                    </div>
                  )}

                  {/* Geolocation Details Grid */}
                  <div className="grid grid-cols-2 gap-2.5 text-xs font-mono bg-slate-950/70 p-3 rounded-xl border border-slate-800/80">
                    <div>
                      <span className="text-[10px] uppercase text-slate-500 block">State / Region</span>
                      <span className="text-slate-200 font-semibold">{selectedMarker.region || '—'}</span>
                    </div>

                    <div>
                      <span className="text-[10px] uppercase text-slate-500 block">Accuracy Radius</span>
                      <span className="text-cyan-400 font-semibold">
                        ±{selectedMarker.accuracy_km || selectedMarker.accuracy_radius || 20} km
                      </span>
                    </div>

                    <div>
                      <span className="text-[10px] uppercase text-slate-500 block">Coordinates</span>
                      <span className="text-slate-300">
                        {selectedMarker.latitude?.toFixed(4)}, {selectedMarker.longitude?.toFixed(4)}
                      </span>
                    </div>

                    <div>
                      <span className="text-[10px] uppercase text-slate-500 block">Severity Rating</span>
                      <span
                        className={`font-bold ${
                          selectedMarker.severity === 'Critical'
                            ? 'text-pink-400'
                            : selectedMarker.severity === 'High'
                            ? 'text-rose-400'
                            : 'text-amber-400'
                        }`}
                      >
                        {selectedMarker.severity}
                      </span>
                    </div>

                    <div>
                      <span className="text-[10px] uppercase text-slate-500 block">Autonomous System</span>
                      <span className="text-slate-300 truncate block">{selectedMarker.asn || 'AS Unknown'}</span>
                    </div>

                    <div>
                      <span className="text-[10px] uppercase text-slate-500 block">ISP / Org</span>
                      <span className="text-slate-300 truncate block">{selectedMarker.org || 'Unspecified'}</span>
                    </div>
                  </div>

                  {/* Attack Categories Observed */}
                  <div className="space-y-1.5">
                    <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                      Attack Signatures Detected
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedMarker.categories?.map((cat) => (
                        <span
                          key={cat}
                          className="px-2 py-0.5 rounded text-[11px] font-mono bg-rose-500/10 text-rose-300 border border-rose-500/30"
                        >
                          {cat}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* First & Last Detected Timestamps */}
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-2 border-t border-slate-800">
                    <span>First Seen: {selectedMarker.first_seen || 'Recent'}</span>
                    <span>Last Seen: {selectedMarker.last_seen || 'Live'}</span>
                  </div>

                  {/* AI Copilot Investigation Button */}
                  <div className="pt-2 border-t border-slate-800 space-y-2">
                    <button
                      onClick={() => handleOpenGeminiInvestigation(selectedMarker.primary_incident_id)}
                      className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-xs font-bold bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 shadow-lg shadow-cyan-500/20 transition-all cursor-pointer"
                    >
                      <Sparkles className="w-3.5 h-3.5 fill-current" />
                      <span>Investigate Incident with Gemini AI</span>
                    </button>

                    <button
                      onClick={() => {
                        const ip = selectedMarker.source_ips?.[0];
                        if (ip) {
                          setLookupIp(ip);
                          setActiveSubTab('lookup');
                          handleRunLookup(ip);
                        }
                      }}
                      className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded-xl text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-all cursor-pointer"
                    >
                      <Crosshair className="w-3.5 h-3.5" />
                      <span>Deep IP Inspector & Provenance</span>
                    </button>
                  </div>
                </div>
              ) : selectedCountry ? (
                /* Fallback to Selected Country Intelligence Card */
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
                      <div className="text-[10px] text-slate-500 uppercase font-mono">Threat Weight</div>
                      <span className="inline-block mt-0.5 px-2.5 py-1 rounded-lg text-xs font-extrabold font-mono bg-gradient-to-r from-rose-500/20 to-pink-500/20 text-rose-400 border border-rose-500/40">
                        ⚡ {selectedCountry.intensity_score}
                      </span>
                    </div>
                  </div>

                  {/* 3 Metric Pills */}
                  <div className="grid grid-cols-3 gap-2 text-center">
                    <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800/80">
                      <div className="text-[10px] text-slate-500 uppercase font-mono">Events</div>
                      <div className="text-base font-bold font-mono text-cyan-400 mt-0.5">{selectedCountry.incident_count}</div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800/80">
                      <div className="text-[10px] text-slate-500 uppercase font-mono">Unique IPs</div>
                      <div className="text-base font-bold font-mono text-emerald-400 mt-0.5">{selectedCountry.unique_ips}</div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800/80">
                      <div className="text-[10px] text-slate-500 uppercase font-mono">Max Sev</div>
                      <div className="text-base font-bold font-mono text-rose-400 mt-0.5">{selectedCountry.max_severity || 'High'}</div>
                    </div>
                  </div>

                  {/* Top Category */}
                  <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 text-xs">
                    <span className="text-slate-500 block text-[10px] uppercase font-mono">Primary Attack Type</span>
                    <span className="text-white font-semibold font-mono text-sm mt-0.5 block">
                      {selectedCountry.top_category || 'Suspicious Ingress Probe'}
                    </span>
                  </div>

                  <button
                    onClick={() => setCountryFilter(selectedCountry.country)}
                    className="w-full flex items-center justify-center gap-1.5 py-2 rounded-xl text-xs font-bold bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 transition-all cursor-pointer"
                  >
                    <Filter className="w-3.5 h-3.5" />
                    <span>Filter Map to {selectedCountry.country}</span>
                  </button>
                </div>
              ) : (
                <div className="p-8 rounded-2xl bg-[#090D16] border border-slate-800 text-center text-xs text-slate-500">
                  Click any hotspot or nation on the map to inspect live source intelligence.
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

                <div className="mt-3 space-y-2">
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
                          <span className="font-mono text-rose-400 font-bold">⚡ {c.intensity_score} pts</span>
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

          {/* ================================================================= */}
          {/* LIVE ATTACK FEED TICKER & WAR ROOM PANELS (Matching Reference 2) */}
          {/* ================================================================= */}
          <div className="p-5 rounded-2xl bg-[#090D16] border border-slate-800 shadow-2xl space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-3 border-b border-slate-800 gap-2">
              <div className="flex items-center gap-2.5">
                <div className="w-3 h-3 rounded-full bg-rose-500 animate-ping" />
                <h3 className="text-sm font-bold text-white tracking-wide uppercase font-mono">
                  Real-Time Live Attack Feed & Target Surveillance
                </h3>
                <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/30">
                  {data?.live_attack_ticker?.length || 0} Ingestion Flows
                </span>
              </div>

              <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
                <span>Sensor: Vadodara SOC Ingestion Edge</span>
                <span>&bull;</span>
                <span className="text-emerald-400">Status: Active</span>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
              {/* Left 1 Col: ATTACK TARGETS */}
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-3">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5 pb-2 border-b border-slate-800">
                  <Target className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Attack Targets</span>
                </div>

                <div className="space-y-2 text-xs">
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="font-semibold text-white flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-400" />
                      Sentinel Ingestion Gateway
                    </div>
                    <div className="text-[11px] font-mono text-cyan-400 mt-1">10.10.213.36 (Vadodara HQ)</div>
                    <div className="text-[10px] text-slate-500 mt-0.5">22.3072° N, 73.1812° E</div>
                  </div>

                  <div className="space-y-1 text-[11px] font-mono text-slate-400">
                    <div className="flex justify-between">
                      <span>Port 22 (SSH Probe):</span>
                      <span className="text-rose-400 font-bold">Monitored</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Port 80/443 (HTTP/S):</span>
                      <span className="text-emerald-400 font-bold">Protected</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Port 8000 (FastAPI):</span>
                      <span className="text-cyan-400 font-bold">Ingesting</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Center 2 Cols: LIVE ATTACK FEED TABLE */}
              <div className="lg:col-span-2 p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-2 flex flex-col justify-between">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center justify-between pb-2 border-b border-slate-800">
                  <span className="flex items-center gap-1.5">
                    <Activity className="w-3.5 h-3.5 text-rose-400" />
                    <span>Live Ingestion Telemetry</span>
                  </span>
                  <span className="text-[10px] font-mono text-slate-500">Direct SQLite Logs</span>
                </div>

                <div className="overflow-x-auto max-h-[220px] overflow-y-auto pr-1">
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="text-[10px] text-slate-500 border-b border-slate-800/60 uppercase">
                        <th className="pb-1.5">Time</th>
                        <th className="pb-1.5">Origin</th>
                        <th className="pb-1.5">Target</th>
                        <th className="pb-1.5">Threat</th>
                        <th className="pb-1.5">Severity</th>
                        <th className="pb-1.5 text-right">Delay</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/40">
                      {data?.live_attack_ticker && data.live_attack_ticker.length > 0 ? (
                        data.live_attack_ticker.map((ev, idx) => (
                          <tr
                            key={idx}
                            onClick={() => {
                              setLookupIp(ev.src_ip);
                              setActiveSubTab('lookup');
                              handleRunLookup(ev.src_ip);
                            }}
                            className="hover:bg-slate-900/80 cursor-pointer transition-colors"
                          >
                            <td className="py-1.5 text-slate-400 text-[11px] whitespace-nowrap">
                              {ev.timestamp ? ev.timestamp.split('T')[1]?.slice(0, 8) || ev.timestamp : 'Live'}
                            </td>
                            <td className="py-1.5 whitespace-nowrap">
                              <span className="text-white font-semibold flex items-center gap-1">
                                <span className="text-cyan-400">{ev.src_ip}</span>
                                {ev.city && <span className="text-slate-500 text-[10px]">({ev.city})</span>}
                              </span>
                            </td>
                            <td className="py-1.5 text-slate-400 whitespace-nowrap">
                              :{ev.dst_port}
                            </td>
                            <td className="py-1.5 whitespace-nowrap">
                              <span className="text-rose-300 font-sans">{ev.category}</span>
                            </td>
                            <td className="py-1.5 whitespace-nowrap">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  ev.severity === 'Critical'
                                    ? 'bg-pink-500/20 text-pink-400 border border-pink-500/30'
                                    : ev.severity === 'High'
                                    ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                                    : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                }`}
                              >
                                {ev.severity}
                              </span>
                            </td>
                            <td className="py-1.5 text-right text-cyan-400 text-[10px] whitespace-nowrap">
                              {ev.ingestion_delay_ms || 22}ms
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={6} className="text-center py-6 text-slate-500">
                            Awaiting incoming network telemetry...
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Right 1 Col: NATURE OF ATTACKS BREAKDOWN */}
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-3">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5 pb-2 border-b border-slate-800">
                  <Shield className="w-3.5 h-3.5 text-rose-400" />
                  <span>Nature of Attacks</span>
                </div>

                <div className="space-y-2 text-xs">
                  {[
                    { label: 'Brute Force Probes', pct: 44, color: 'from-rose-500 to-pink-500' },
                    { label: 'Port Scan Sweeps', pct: 28, color: 'from-amber-500 to-orange-500' },
                    { label: 'DDoS Surges', pct: 16, color: 'from-purple-500 to-indigo-500' },
                    { label: 'Web Reconnaissance', pct: 12, color: 'from-cyan-500 to-blue-500' },
                  ].map((atk) => (
                    <div key={atk.label} className="space-y-1">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-slate-300">{atk.label}</span>
                        <span className="font-mono text-slate-400">{atk.pct}%</span>
                      </div>
                      <div className="w-full h-1.5 rounded-full bg-slate-900 overflow-hidden">
                        <div
                          className={`h-full rounded-full bg-gradient-to-r ${atk.color}`}
                          style={{ width: `${atk.pct}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* SUB-TAB 2: LOCAL NETWORK TOPOLOGY (RFC 1918 / LOOPBACK) */}
      {/* ===================================================================== */}
      {activeSubTab === 'topology' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-purple-400" />
              Private Local Network Topology (RFC 1918 / Loopback)
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              SentinelAI explicitly segregates unroutable internal addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and 127.0.0.1) from the public world map.
              These nodes represent local testing injectors, switch interfaces, and LAN hosts.
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
                        <span key={c} className="px-1.5 py-0.5 rounded text-[9px] bg-slate-800 text-slate-300">
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
                    className="w-full text-center py-1.5 rounded-lg text-[11px] font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer"
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
              Query any IPv4 address against MaxMind GeoLite2 City binary (.mmdb) and cross-reference with stored SQLite network logs and incidents.
            </p>

            <div className="flex flex-col sm:flex-row items-center gap-3 pt-2">
              <div className="relative flex-1 w-full">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={lookupIp}
                  onChange={(e) => setLookupIp(e.target.value)}
                  placeholder="Enter IP address (e.g. 103.235.91.132, 128.30.52.100, 10.10.213.36)"
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
                  setLookupIp('103.235.91.132');
                  handleRunLookup('103.235.91.132');
                }}
                className="px-2 py-0.5 rounded bg-slate-800 text-rose-300 font-mono text-[11px] hover:bg-slate-700 cursor-pointer"
              >
                103.235.91.132 (Gujarat, IN)
              </button>
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
                  setLookupIp('10.10.213.36');
                  handleRunLookup('10.10.213.36');
                }}
                className="px-2 py-0.5 rounded bg-slate-800 text-purple-300 font-mono text-[11px] hover:bg-slate-700 cursor-pointer"
              >
                10.10.213.36 (RFC 1918 Private)
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
                    <span className="text-cyan-400 font-semibold">
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

      {/* ===================================================================== */}
      {/* MODAL 1: AUTHORIZED TEST ATTACK TRAFFIC GENERATOR */}
      {/* ===================================================================== */}
      {showSimulateModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[#090D16] border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-rose-500/20 text-rose-400 flex items-center justify-center">
                  <Zap className="w-4 h-4 fill-current" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">Generate Authorized Attack Test Traffic</h3>
                  <p className="text-[11px] text-slate-400">Trigger real-world attack detection & live map shockwaves</p>
                </div>
              </div>

              <button
                onClick={() => setShowSimulateModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-850 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-300">
              Simulate authorized attack telemetry to verify network ingestion, MaxMind GeoLite2 geographic resolution, SQLite storage, and glowing heat spot visualization.
            </p>

            {/* Presets */}
            <div className="space-y-1.5">
              <span className="text-[10px] uppercase font-mono text-slate-500">Quick Test Source Presets (Worldwide Hotspots):</span>
              <div className="flex flex-wrap gap-1.5 text-xs">
                <button
                  type="button"
                  onClick={() => {
                    setSimIp('103.235.91.132');
                    setSimAttackType('Brute Force');
                    setSimTargetPort(22);
                    setSimSeverity('High');
                  }}
                  className="px-2 py-1 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-500/40 text-cyan-300 text-[10px] font-mono cursor-pointer"
                >
                  💻 My Laptop IP (Gujarat, India)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSimIp('133.242.0.1');
                    setSimAttackType('DDoS Surge');
                    setSimTargetPort(80);
                    setSimSeverity('Critical');
                  }}
                  className="px-2 py-1 rounded-lg bg-slate-900 border border-slate-800 hover:border-rose-500/40 text-rose-300 text-[10px] font-mono cursor-pointer"
                >
                  🇯🇵 Tokyo Sensor (Japan)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSimIp('128.30.52.100');
                    setSimAttackType('Port Scan');
                    setSimTargetPort(80);
                    setSimSeverity('Critical');
                  }}
                  className="px-2 py-1 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-500/40 text-cyan-300 text-[10px] font-mono cursor-pointer"
                >
                  🇺🇸 MIT Campus (Boston, US)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSimIp('198.51.100.23');
                    setSimAttackType('Web Reconnaissance');
                    setSimTargetPort(443);
                    setSimSeverity('High');
                  }}
                  className="px-2 py-1 rounded-lg bg-slate-900 border border-slate-800 hover:border-amber-500/40 text-amber-300 text-[10px] font-mono cursor-pointer"
                >
                  🇨🇭 Zurich Node (Switzerland)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSimIp('198.51.100.99');
                    setSimAttackType('Data Exfiltration');
                    setSimTargetPort(8080);
                    setSimSeverity('High');
                  }}
                  className="px-2 py-1 rounded-lg bg-slate-900 border border-slate-800 hover:border-amber-500/40 text-amber-300 text-[10px] font-mono cursor-pointer"
                >
                  🇩🇪 Frankfurt Cloud (Germany)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSimIp('1.1.1.1');
                    setSimAttackType('Port Scan');
                    setSimTargetPort(53);
                    setSimSeverity('Medium');
                  }}
                  className="px-2 py-1 rounded-lg bg-slate-900 border border-slate-800 hover:border-emerald-500/40 text-emerald-300 text-[10px] font-mono cursor-pointer"
                >
                  🇦🇺 Sydney Edge (Australia)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSimIp('10.10.213.36');
                    setSimAttackType('Internal Pivot');
                    setSimTargetPort(445);
                    setSimSeverity('Medium');
                  }}
                  className="px-2 py-1 rounded-lg bg-slate-900 border border-slate-800 hover:border-purple-500/40 text-purple-300 text-[10px] font-mono cursor-pointer"
                >
                  🔒 Local LAN (10.10.213.36)
                </button>
              </div>
            </div>

            {/* Form Fields */}
            <div className="space-y-3 pt-2 text-xs">
              <div>
                <label className="text-[11px] font-semibold text-slate-300 block mb-1">
                  Source IP Address
                </label>
                <input
                  type="text"
                  value={simIp}
                  onChange={(e) => setSimIp(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 font-mono text-white text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-semibold text-slate-300 block mb-1">
                    Attack Category
                  </label>
                  <select
                    value={simAttackType}
                    onChange={(e) => setSimAttackType(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 font-mono text-white text-xs focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Brute Force">Brute Force</option>
                    <option value="Port Scan">Port Scan</option>
                    <option value="DDoS Surge">DDoS Surge</option>
                    <option value="Web Reconnaissance">Web Reconnaissance</option>
                    <option value="Data Exfiltration">Data Exfiltration</option>
                  </select>
                </div>

                <div>
                  <label className="text-[11px] font-semibold text-slate-300 block mb-1">
                    Severity
                  </label>
                  <select
                    value={simSeverity}
                    onChange={(e) => setSimSeverity(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 font-mono text-white text-xs focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Critical">Critical (Weight 5)</option>
                    <option value="High">High (Weight 4)</option>
                    <option value="Medium">Medium (Weight 2)</option>
                    <option value="Low">Low (Weight 1)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-semibold text-slate-300 block mb-1">
                    Target Destination Port
                  </label>
                  <input
                    type="number"
                    value={simTargetPort}
                    onChange={(e) => setSimTargetPort(Number(e.target.value))}
                    className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 font-mono text-white text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="text-[11px] font-semibold text-slate-300 block mb-1">
                    Event Packet Count
                  </label>
                  <select
                    value={simEventCount}
                    onChange={(e) => setSimEventCount(Number(e.target.value))}
                    className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 font-mono text-white text-xs focus:outline-none focus:border-cyan-500"
                  >
                    <option value={1}>1 event</option>
                    <option value={3}>3 events (Burst)</option>
                    <option value={5}>5 events (Heavy Probe)</option>
                    <option value={10}>10 events (Surge)</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Feedback Alert */}
            {simFeedback && (
              <div
                className={`p-3 rounded-xl text-xs ${
                  simFeedback.type === 'success'
                    ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
                    : 'bg-rose-500/10 border border-rose-500/30 text-rose-300'
                }`}
              >
                <div className="font-semibold">{simFeedback.message}</div>
                {simFeedback.details && (
                  <div className="text-[11px] font-mono mt-1 text-slate-300">
                    Resolved: {simFeedback.details.city}, {simFeedback.details.country} (Lat: {simFeedback.details.latitude}, Lon: {simFeedback.details.longitude}, Acc: ±{simFeedback.details.accuracy_km || 20}km)
                  </div>
                )}
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowSimulateModal(false)}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white cursor-pointer"
              >
                Close
              </button>
              <button
                type="button"
                onClick={handleSimulateAttack}
                disabled={simulating}
                className="flex items-center gap-2 px-5 py-2 rounded-xl text-xs font-bold bg-rose-500 hover:bg-rose-400 text-white shadow-lg shadow-rose-500/20 cursor-pointer"
              >
                {simulating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                <span>Inject Attack Telemetry</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* MODAL 2: GEMINI AI COPILOT INCIDENT INVESTIGATION */}
      {/* ===================================================================== */}
      {copilotModalOpen && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-[#090D16] border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-cyan-500/20 text-cyan-400 flex items-center justify-center">
                  <Sparkles className="w-4 h-4 fill-current" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">Gemini Security Copilot &bull; Incident Investigation</h3>
                  <p className="text-[11px] font-mono text-cyan-400">
                    Incident ID: {copilotData?.incidentId || 'Correlating...'}
                  </p>
                </div>
              </div>

              <button
                onClick={() => setCopilotModalOpen(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {copilotLoading ? (
              <div className="py-12 flex flex-col items-center justify-center gap-3 text-cyan-400 font-mono text-xs">
                <RefreshCw className="w-6 h-6 animate-spin" />
                <span>Querying Google Gemini Live Threat Model & Correlating SQLite Evidence...</span>
              </div>
            ) : copilotError ? (
              <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
                {copilotError}
              </div>
            ) : copilotData ? (
              <div className="space-y-4 text-xs">
                {/* Executive Summary */}
                <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                  <div className="text-[10px] uppercase font-mono text-cyan-400 font-bold">Executive Incident Summary</div>
                  <p className="text-slate-200 leading-relaxed">{copilotData.explanation?.summary}</p>
                </div>

                {/* Technical Mechanism */}
                <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                  <div className="text-[10px] uppercase font-mono text-rose-400 font-bold">Observed Attack Mechanism</div>
                  <p className="text-slate-300 font-mono text-[11px] leading-relaxed">{copilotData.explanation?.mechanism}</p>
                </div>

                {/* Dual Hypotheses */}
                <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                  <div className="text-[10px] uppercase font-mono text-amber-400 font-bold">Threat Hypotheses & Likelihood</div>
                  <p className="text-slate-300 leading-relaxed">{copilotData.explanation?.threat_hypotheses}</p>
                </div>

                {/* Recommended Defensive Actions */}
                <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                  <div className="text-[10px] uppercase font-mono text-emerald-400 font-bold">Recommended Containment Actions</div>
                  <p className="text-slate-300 leading-relaxed">{copilotData.explanation?.recommended_actions}</p>
                </div>

                {/* Confidence & Provider */}
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-2 border-t border-slate-800">
                  <span>Provider: {copilotData.explanation?.provider || 'Google Gemini Pro / Local Sentinel Engine'}</span>
                  <span>Confidence: {((copilotData.explanation?.confidence_score || 0.92) * 100).toFixed(0)}%</span>
                </div>

                {/* AI Advisory Disclaimer */}
                <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-[10px] text-amber-300">
                  {copilotData.explanation?.ai_disclaimer ||
                    'AI analysis is advisory only. Autonomous firewall modification based solely on AI output is strictly prohibited.'}
                </div>
              </div>
            ) : null}

            <div className="flex items-center justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setCopilotModalOpen(false)}
                className="px-5 py-2 rounded-xl text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatIntelligencePage;
