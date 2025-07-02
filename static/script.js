document.querySelectorAll("button").forEach(btn => {
    btn.addEventListener("click", () => {
        alert("商品已加入購物車（僅前端示意）");
    });
});
function openProfileModal() {
  const modal = document.getElementById("profile-modal");
  if (modal) {
    modal.style.display = "block";

    // 自動載入會員資料
    fetch("/profile-data")
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          document.getElementById("name").value = data.data.name || "";
          document.getElementById("phone").value = data.data.phone || "";
          document.getElementById("address").value = data.data.address || "";
          document.getElementById("note").value = data.data.note || "";
        }
      });
  }
}

function closeProfileModal() {
  const modal = document.getElementById("profile-modal");
  if (modal) {
    modal.style.display = "none";
  }
}

window.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get("profile_saved") === "1") {
    const box = document.getElementById("save-success");
    if (box) {
      box.style.display = 'block';
      setTimeout(() => {
        box.style.display = 'none';
      }, 2000);
    }
  }
});
