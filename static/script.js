




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

let initialProfileData = {};
let closeRequested = false;

function openProfileModal() {
  fetch('/get_profile')
    .then(res => res.json())
    .then(data => {
      document.getElementById("name").value = data.name || '';
      document.getElementById("phone").value = data.phone || '';
      document.getElementById("address").value = data.address || '';
      document.getElementById("note").value = data.note || '';
      document.getElementById("profile-modal").style.display = "block";

      initialProfileData = {
        name: data.name || '',
        phone: data.phone || '',
        address: data.address || ''
      };
    });
}

function closeProfileModal() {
  const current = {
    name: document.getElementById("name").value.trim(),
    phone: document.getElementById("phone").value.trim(),
    address: document.getElementById("address").value.trim()
  };

  const hasChanged = Object.keys(initialProfileData).some(
    key => current[key] !== initialProfileData[key]
  );

  if (hasChanged) {
    // 顯示自訂警告視窗
    document.getElementById("unsaved-warning").style.display = "block";
  } else {
    // 沒改就直接關
    document.getElementById("profile-modal").style.display = "none";
  }
}

function cancelCloseProfile() {
  document.getElementById("unsaved-warning").style.display = "none";
}

function confirmCloseProfile() {
  document.getElementById("unsaved-warning").style.display = "none";
  document.getElementById("profile-modal").style.display = "none";
}

let currentCategory = null;

// ===== 初始化浮動購物車數量（從 header 同步）=====
document.addEventListener("DOMContentLoaded", () => {
  const headerCount = document.getElementById("cart-count");        // 上方購物車
  const floatingCount = document.getElementById("floating-cart-count"); // 右下浮動

  if (!floatingCount) return;

  let n = 0;
  if (headerCount) {
    n = parseInt(headerCount.textContent || "0", 10);
  }

  if (n > 0) {
    floatingCount.textContent = n;
    floatingCount.style.display = "flex";
  } else {
    floatingCount.style.display = "none";
  }
});
