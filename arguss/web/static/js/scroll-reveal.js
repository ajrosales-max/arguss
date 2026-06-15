const io = new IntersectionObserver((entries) => {
  entries.forEach((e) => {
    if (e.isIntersecting) {
      e.target.classList.add('in-view');
      e.target.querySelectorAll('[data-target]').forEach((el) => {
        const target = +el.dataset.target;
        if (target === 0) return;
        const dur = 1500;
        const start = performance.now();
        function tick(now) {
          const t = Math.min((now - start) / dur, 1);
          el.textContent = Math.round((1 - Math.pow(1 - t, 3)) * target);
          if (t < 1) requestAnimationFrame(tick);
        }
        requestAnimationFrame(tick);
      });
      io.unobserve(e.target);
    }
  });
}, { threshold: 0.1 });
document.querySelectorAll('.sr').forEach((el) => io.observe(el));
