
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

