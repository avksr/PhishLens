// ─────────────────────────────────────────────────────────────
//  PhishLens Enterprise Landing · Interactive Custom Cursor
//  Strictly matched to Stitch screen projects/1873559564137532359
//  Smooth lerped blue cursor with interactive element hover expansion
// ─────────────────────────────────────────────────────────────
import { useEffect, useRef } from 'react';

export function CustomCursor() {
  const cursorRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const isTouch = window.matchMedia('(pointer: coarse)').matches;
    if (isTouch) return;

    let mouseX = window.innerWidth / 2;
    let mouseY = window.innerHeight / 2;
    let cursorX = mouseX;
    let cursorY = mouseY;
    let rafId: number;

    const onMouseMove = (e: MouseEvent) => {
      mouseX = e.clientX;
      mouseY = e.clientY;
    };

    window.addEventListener('mousemove', onMouseMove, { passive: true });

    const render = () => {
      cursorX += (mouseX - cursorX) * 0.22;
      cursorY += (mouseY - cursorY) * 0.22;
      if (cursorRef.current) {
        cursorRef.current.style.transform = `translate3d(${cursorX}px, ${cursorY}px, 0) translate(-50%, -50%)`;
      }
      rafId = requestAnimationFrame(render);
    };

    rafId = requestAnimationFrame(render);

    const onMouseEnterInteractive = () => {
      cursorRef.current?.classList.add('custom-cursor-hover');
    };

    const onMouseLeaveInteractive = () => {
      cursorRef.current?.classList.remove('custom-cursor-hover');
    };

    // Attach listeners to interactive elements
    const elements = document.querySelectorAll('a, button, input, .sample-chip');
    elements.forEach(el => {
      el.addEventListener('mouseenter', onMouseEnterInteractive);
      el.addEventListener('mouseleave', onMouseLeaveInteractive);
    });

    return () => {
      window.removeEventListener('mousemove', onMouseMove);
      cancelAnimationFrame(rafId);
      elements.forEach(el => {
        el.removeEventListener('mouseenter', onMouseEnterInteractive);
        el.removeEventListener('mouseleave', onMouseLeaveInteractive);
      });
    };
  }, []);

  return <div ref={cursorRef} id="cursor-dot" className="custom-cursor-dot" />;
}
