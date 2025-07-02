document.querySelectorAll("button").forEach(btn => {
    btn.addEventListener("click", () => {
        alert("商品已加入購物車（僅前端示意）");
    });
});
function openProfileModal() {
  const modal = document.getElementById("profile-modal");
  if (modal) {
    modal.style.display = "block";
  }
}

function closeProfileModal() {
  const modal = document.getElementById("profile-modal");
  if (modal) {
    modal.style.display = "none";
  }
}
