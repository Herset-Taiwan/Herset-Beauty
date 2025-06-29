document.querySelectorAll('.combo-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    alert(`你選擇了：${btn.textContent}`);
  });
});
