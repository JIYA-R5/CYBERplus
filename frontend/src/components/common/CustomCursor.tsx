import React, { useEffect, useRef } from 'react';

/**
 * CustomCursor Component
 *
 * Futuristic Tactical Reticle HUD Cursor:
 * 1. Slow 360° Continuous Rotation:
 *    - Four-corner reticle rotates continuously through 360° at 18s per full cycle.
 *    - Rotation runs on an independent high-resolution time clock without resetting.
 *
 * 2. Dynamic Button Capture:
 *    - When hovering over or across any button, smoothly expands and aligns
 *      its four corner brackets precisely to the button's outer bounding rectangle.
 *    - Decoupled from rotation so corner brackets lock orthogonally onto the button corners.
 *    - The central dot stays attached to the actual mouse position at native refresh rate.
 *
 * 3. Color Changing & Feedback:
 *    - Default: Pure White (#FFFFFF) with crisp black contrast stroke.
 *    - Interactive / Buttons / Links: Electric Cyan (#00F5FF).
 *    - Danger / Critical actions: Neon Rose (#FF2E63).
 *    - Active Click: Tactile snap scale feedback.
 */
export const CustomCursor: React.FC = () => {
  const rootRef = useRef<HTMLDivElement>(null);
  const frameRef = useRef<HTMLDivElement>(null);
  const dotRef = useRef<HTMLDivElement>(null);

  const stateRef = useRef({
    // Mouse coords
    mouseX: -100,
    mouseY: -100,
    hasMoved: false,

    // Interpolated frame position & size
    currentX: -100,
    currentY: -100,
    currentW: 30,
    currentH: 30,

    // Target frame position & size
    targetX: -100,
    targetY: -100,
    targetW: 30,
    targetH: 30,

    // Rotation interpolation weight: 1.0 in compact mode, 0.0 in button-capture mode
    currentRotWeight: 1.0,
    targetRotWeight: 1.0,

    // Capture & visual states
    isCaptured: false,
    isHovered: false,
    isDanger: false,
    isClicking: false,
    capturedEl: null as HTMLElement | null,
  });

  const lastTimeRef = useRef(performance.now());
  const rafIdRef = useRef<number>(0);

  useEffect(() => {
    // Disable custom cursor on touch/coarse devices
    if (window.matchMedia && window.matchMedia('(pointer: coarse)').matches) {
      return;
    }

    const rootEl = rootRef.current;
    const frameEl = frameRef.current;
    const dotEl = dotRef.current;
    if (!rootEl || !frameEl || !dotEl) return;

    const findButton = (el: HTMLElement | null): HTMLElement | null => {
      if (!el) return null;
      return el.closest('button, [role="button"], a.btn, a[role="button"], input[type="submit"], input[type="button"]');
    };

    const findInteractive = (el: HTMLElement | null): HTMLElement | null => {
      if (!el) return null;
      return el.closest('a, button, input, select, textarea, [role="button"], [data-interactive="true"], .cursor-pointer');
    };

    const checkDanger = (el: HTMLElement | null): boolean => {
      if (!el) return false;
      return !!el.closest('.bg-rose-500, .bg-red-500, .text-rose-400, .border-rose-500, .is-danger, [data-danger="true"], [class*="rose"], [class*="red"]');
    };

    const updateTargetFromElement = (target: HTMLElement | null) => {
      const state = stateRef.current;
      const buttonEl = findButton(target);
      const interactiveEl = findInteractive(target);
      const isDangerEl = checkDanger(target);

      state.isDanger = isDangerEl;

      if (buttonEl) {
        state.isCaptured = true;
        state.isHovered = true;
        state.capturedEl = buttonEl;
        state.targetRotWeight = 0.0;

        const rect = buttonEl.getBoundingClientRect();
        const pad = 3;
        state.targetW = rect.width + pad * 2;
        state.targetH = rect.height + pad * 2;
        state.targetX = rect.left + rect.width / 2;
        state.targetY = rect.top + rect.height / 2;
      } else {
        state.isCaptured = false;
        state.capturedEl = null;
        state.isHovered = !!interactiveEl;
        state.targetRotWeight = 1.0;

        state.targetW = 30;
        state.targetH = 30;
        state.targetX = state.mouseX;
        state.targetY = state.mouseY;
      }
    };

    const handlePointerMove = (e: MouseEvent) => {
      const state = stateRef.current;
      state.mouseX = e.clientX;
      state.mouseY = e.clientY;

      if (!state.hasMoved) {
        state.hasMoved = true;
        state.currentX = e.clientX;
        state.currentY = e.clientY;
        state.targetX = e.clientX;
        state.targetY = e.clientY;
        rootEl.style.opacity = '1';
      }

      updateTargetFromElement(e.target as HTMLElement | null);
    };

    const handleScroll = () => {
      const state = stateRef.current;
      if (state.isCaptured && state.capturedEl) {
        if (!state.capturedEl.isConnected) {
          state.isCaptured = false;
          state.capturedEl = null;
          state.targetRotWeight = 1.0;
          state.targetW = 30;
          state.targetH = 30;
          state.targetX = state.mouseX;
          state.targetY = state.mouseY;
        } else {
          const rect = state.capturedEl.getBoundingClientRect();
          const pad = 3;
          state.targetW = rect.width + pad * 2;
          state.targetH = rect.height + pad * 2;
          state.targetX = rect.left + rect.width / 2;
          state.targetY = rect.top + rect.height / 2;
        }
      }
    };

    const handleMouseDown = () => {
      stateRef.current.isClicking = true;
    };

    const handleMouseUp = () => {
      stateRef.current.isClicking = false;
    };

    const handleMouseLeave = () => {
      rootEl.style.opacity = '0';
    };

    const handleMouseEnter = () => {
      if (stateRef.current.hasMoved) {
        rootEl.style.opacity = '1';
      }
    };

    window.addEventListener('pointermove', handlePointerMove, { passive: true });
    window.addEventListener('scroll', handleScroll, { passive: true });
    window.addEventListener('mousedown', handleMouseDown, { passive: true });
    window.addEventListener('mouseup', handleMouseUp, { passive: true });
    document.addEventListener('mouseleave', handleMouseLeave);
    document.addEventListener('mouseenter', handleMouseEnter);

    // Animation loop (144Hz / 60Hz frame-rate independent via exponential decay)
    const animate = (timestamp: number) => {
      const state = stateRef.current;
      const dt = Math.min((timestamp - lastTimeRef.current) / 1000, 0.1);
      lastTimeRef.current = timestamp;

      // Keep captured button coordinates freshly updated if button animated or moved
      if (state.isCaptured && state.capturedEl) {
        if (!state.capturedEl.isConnected) {
          state.isCaptured = false;
          state.capturedEl = null;
          state.targetRotWeight = 1.0;
          state.targetW = 30;
          state.targetH = 30;
          state.targetX = state.mouseX;
          state.targetY = state.mouseY;
        } else {
          const rect = state.capturedEl.getBoundingClientRect();
          const pad = 3;
          state.targetW = rect.width + pad * 2;
          state.targetH = rect.height + pad * 2;
          state.targetX = rect.left + rect.width / 2;
          state.targetY = rect.top + rect.height / 2;
        }
      } else if (!state.isCaptured) {
        state.targetX = state.mouseX;
        state.targetY = state.mouseY;
      }

      // Smooth exponential decay interpolation
      const posRate = state.isCaptured ? 24 : 45;
      const posFactor = 1 - Math.exp(-posRate * dt);
      const sizeFactor = 1 - Math.exp(-22 * dt);
      const rotFactor = 1 - Math.exp(-18 * dt);

      state.currentX += (state.targetX - state.currentX) * posFactor;
      state.currentY += (state.targetY - state.currentY) * posFactor;
      state.currentW += (state.targetW - state.currentW) * sizeFactor;
      state.currentH += (state.targetH - state.currentH) * sizeFactor;
      state.currentRotWeight += (state.targetRotWeight - state.currentRotWeight) * rotFactor;

      // Independent continuous 360° rotation (one rotation every 18 seconds = 18000ms)
      const continuousAngle = ((timestamp / 18000) * 360) % 360;
      const effectiveAngle = continuousAngle * state.currentRotWeight;

      // Click scale feedback
      const frameScale = state.isClicking ? 0.95 : 1.0;
      const dotScale = state.isClicking ? 1.4 : (state.isHovered ? 1.15 : 1.0);

      // Render 4-corners frame
      const posX = state.currentX - state.currentW / 2;
      const posY = state.currentY - state.currentH / 2;
      frameEl.style.transform = `translate3d(${posX.toFixed(2)}px, ${posY.toFixed(2)}px, 0) rotate(${effectiveAngle.toFixed(2)}deg) scale(${frameScale})`;
      frameEl.style.width = `${state.currentW.toFixed(1)}px`;
      frameEl.style.height = `${state.currentH.toFixed(1)}px`;

      // Render central dot (attached strictly to actual mouse position)
      dotEl.style.transform = `translate3d(${state.mouseX.toFixed(2)}px, ${state.mouseY.toFixed(2)}px, 0) scale(${dotScale})`;

      // Dynamic color transitions
      let activeColor = '#FFFFFF';
      let activeGlow = 'drop-shadow(0 0 1px #000000)';

      if (state.isDanger) {
        activeColor = '#FF2E63';
        activeGlow = 'drop-shadow(0 0 1px #000000) drop-shadow(0 0 5px rgba(255, 46, 99, 0.75))';
      } else if (state.isHovered) {
        activeColor = '#00F5FF';
        activeGlow = 'drop-shadow(0 0 1px #000000) drop-shadow(0 0 4px rgba(0, 245, 255, 0.7))';
      }

      if (frameEl.style.color !== activeColor) {
        frameEl.style.color = activeColor;
        frameEl.style.filter = activeGlow;
        dotEl.style.color = activeColor;
        dotEl.style.filter = activeGlow;
      }

      rafIdRef.current = requestAnimationFrame(animate);
    };

    rafIdRef.current = requestAnimationFrame(animate);

    return () => {
      cancelAnimationFrame(rafIdRef.current);
      window.removeEventListener('pointermove', handlePointerMove);
      window.removeEventListener('scroll', handleScroll);
      window.removeEventListener('mousedown', handleMouseDown);
      window.removeEventListener('mouseup', handleMouseUp);
      document.removeEventListener('mouseleave', handleMouseLeave);
      document.removeEventListener('mouseenter', handleMouseEnter);
    };
  }, []);

  return (
    <div
      ref={rootRef}
      className="fixed inset-0 pointer-events-none select-none z-[999999] overflow-hidden"
      style={{ opacity: 0, transition: 'opacity 0.2s ease' }}
      aria-hidden="true"
    >
      {/* Central Aiming Dot (Pinned directly to actual mouse coordinates) */}
      <div
        ref={dotRef}
        className="fixed top-0 left-0 pointer-events-none will-change-transform"
        style={{
          color: '#FFFFFF',
          filter: 'drop-shadow(0 0 1px #000000)',
          transition: 'color 0.15s ease, filter 0.15s ease',
        }}
      >
        <svg
          width="10"
          height="10"
          viewBox="0 0 10 10"
          fill="none"
          className="overflow-visible block"
          style={{ transform: 'translate(-50%, -50%)' }}
        >
          <circle cx="5" cy="5" r="3.4" fill="#000000" />
          <circle cx="5" cy="5" r="2.2" fill="currentColor" />
        </svg>
      </div>

      {/* Four-Corner Tactical Reticle Frame */}
      <div
        ref={frameRef}
        className="fixed top-0 left-0 pointer-events-none will-change-transform"
        style={{
          width: '30px',
          height: '30px',
          color: '#FFFFFF',
          filter: 'drop-shadow(0 0 1px #000000)',
          transition: 'color 0.15s ease, filter 0.15s ease',
        }}
      >
        {/* Corner 1: Top-Left */}
        <svg
          width="10"
          height="10"
          viewBox="0 0 10 10"
          fill="none"
          className="absolute top-0 left-0 overflow-visible pointer-events-none"
        >
          <path
            d="M 0.5 9.5 L 0.5 0.5 L 9.5 0.5"
            stroke="#000000"
            strokeWidth="3.4"
            strokeLinecap="square"
            strokeLinejoin="miter"
          />
          <path
            d="M 0.5 9.5 L 0.5 0.5 L 9.5 0.5"
            stroke="currentColor"
            strokeWidth="1.9"
            strokeLinecap="square"
            strokeLinejoin="miter"
          />
        </svg>

        {/* Corner 2: Top-Right */}
        <svg
          width="10"
          height="10"
          viewBox="0 0 10 10"
          fill="none"
          className="absolute top-0 right-0 overflow-visible pointer-events-none"
        >
          <path
            d="M 0.5 0.5 L 9.5 0.5 L 9.5 9.5"
            stroke="#000000"
            strokeWidth="3.4"
            strokeLinecap="square"
            strokeLinejoin="miter"
          />
          <path
            d="M 0.5 0.5 L 9.5 0.5 L 9.5 9.5"
            stroke="currentColor"
            strokeWidth="1.9"
            strokeLinecap="square"
            strokeLinejoin="miter"
          />
        </svg>

        {/* Corner 3: Bottom-Left */}
        <svg
          width="10"
          height="10"
          viewBox="0 0 10 10"
          fill="none"
          className="absolute bottom-0 left-0 overflow-visible pointer-events-none"
        >
          <path
            d="M 0.5 0.5 L 0.5 9.5 L 9.5 9.5"
            stroke="#000000"
            strokeWidth="3.4"
            strokeLinecap="square"
            strokeLinejoin="miter"
          />
          <path
            d="M 0.5 0.5 L 0.5 9.5 L 9.5 9.5"
            stroke="currentColor"
            strokeWidth="1.9"
            strokeLinecap="square"
            strokeLinejoin="miter"
          />
        </svg>

        {/* Corner 4: Bottom-Right */}
        <svg
          width="10"
          height="10"
          viewBox="0 0 10 10"
          fill="none"
          className="absolute bottom-0 right-0 overflow-visible pointer-events-none"
        >
          <path
            d="M 0.5 9.5 L 9.5 9.5 L 9.5 0.5"
            stroke="#000000"
            strokeWidth="3.4"
            strokeLinecap="square"
            strokeLinejoin="miter"
          />
          <path
            d="M 0.5 9.5 L 9.5 9.5 L 9.5 0.5"
            stroke="currentColor"
            strokeWidth="1.9"
            strokeLinecap="square"
            strokeLinejoin="miter"
          />
        </svg>
      </div>
    </div>
  );
};

export default CustomCursor;
