// ==============================
// Theme Toggle Functionality
// ==============================
document.addEventListener('DOMContentLoaded', function() {
    const themeToggle = document.getElementById('theme-toggle'); // Theme toggle switch
    const label = document.querySelector('.toggle-label'); // Label for the toggle
    const body = document.body; // Reference to the body element

    // Check if theme preference is stored in localStorage
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        body.classList.add('dark-mode'); // Apply dark mode if preference is set
        themeToggle.checked = true; // Set toggle switch to checked
        label.textContent = 'Dark Mode'; // Update label text
    } else {
        body.classList.remove('dark-mode'); // Remove dark mode class if preference is light
        label.textContent = 'Light Mode'; // Update label text
    }

    // Event listener for theme toggle
    themeToggle.addEventListener('change', function() {
        if (themeToggle.checked) {
            body.classList.add('dark-mode'); // Enable dark mode
            label.textContent = 'Dark Mode'; // Update label text
            localStorage.setItem('theme', 'dark'); // Store preference in localStorage
        } else {
            body.classList.remove('dark-mode'); // Disable dark mode
            label.textContent = 'Light Mode'; // Update label text
            localStorage.setItem('theme', 'light'); // Store preference in localStorage
        }
    });
});

// ==============================
// Countdown Timer Functionality
// ==============================
document.addEventListener('DOMContentLoaded', function() {
    let endTime = new Date("{{ checkpoint.Checkpoint_EndTime }}").getTime(); // Set end time for countdown
    let countdownElement = document.getElementById("countdown"); // Reference to countdown display

    let countdownInterval = setInterval(function() {
        let now = new Date().getTime(); // Get current time
        let distance = endTime - now; // Calculate remaining time

        // Calculate hours, minutes, and seconds
        let hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        let minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
        let seconds = Math.floor((distance % (1000 * 60)) / 1000);

        // Display the remaining time
        countdownElement.innerHTML = hours + "h " + minutes + "m " + seconds + "s ";

        // Check if countdown has ended
        if (distance < 0) {
            clearInterval(countdownInterval); // Stop the countdown
            countdownElement.innerHTML = "Checkpoint ended!"; // Update display
            if (scanner) {
                scanner.stop(); // Stop the scanner if it exists
            }
        }
    }, 1000); // Update every second
});

// ==============================
// QR Code Scanner Functionality
// ==============================
let scanner; // Declare scanner outside to access in the countdown logic

document.addEventListener('DOMContentLoaded', function() {
    scanner = new Instascan.Scanner({ video: document.getElementById('scanner-video') }); // Initialize the scanner

    // Start scanning when the scan button is clicked
    document.getElementById('scan-button').addEventListener('click', function() {
        Instascan.Camera.getCameras().then(function(cameras) {
            if (cameras.length > 0) {
                scanner.start(cameras[0]); // Start the scanner with the first camera
            } else {
                console.error('No cameras found.'); // Log error if no cameras are available
            }
        }).catch(function(e) {
            console.error(e); // Log any errors during camera retrieval
        });
    });

    // Listen for scanned QR code content
    scanner.addListener('scan', function(content) {
        // Prepare the data object to send to the server
        const requestData = {
            qrCode: content,
            checkpoint_id: '{{ checkpoint.CheckpointID }}' // Ensure this gets replaced correctly by your template engine
        };

        // Send the scanned QR code content to the server
        fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestData) // Make sure to use the requestData variable here
        })
        .then(response => response.json()) // Parse the JSON response
        .then(data => {
            if (data.success) {
                // Show success modal for successful scans
                document.getElementById('capture-success-modal').style.display = 'block';
                setTimeout(() => document.getElementById('capture-success-modal').style.display = 'none', 3000); // Hide after 3 seconds
            } else {
                // Show failure modal for failed scans
                document.getElementById('capture-failure-modal').style.display = 'block';
                setTimeout(() => document.getElementById('capture-failure-modal').style.display = 'none', 3000); // Hide after 3 seconds
            }
        })
        .catch(error => console.error('Error:', error)); // Log any errors from the fetch operation
    });
});

// ==============================
// Flash Messages Functionality
// ==============================
function hideFlashMessages() {
    // Get all flash message elements
    const messages = document.querySelectorAll('.flash-message');

    messages.forEach(message => {
        setTimeout(() => {
            message.classList.add('fade-out'); // Optional: Add fade-out effect
            setTimeout(() => {
                message.style.display = 'none'; // Hide the message
            }, 500); // Delay hiding to allow fade-out effect
        }, 5000); // 5000 milliseconds = 5 seconds
    });
}

// Call the function after the DOM is fully loaded
document.addEventListener('DOMContentLoaded', hideFlashMessages);



// ==============================
// Base.html Images Functionality
// ==============================
document.addEventListener("DOMContentLoaded", function() {
    // Display Current Time Functionality
    function updateTime() {
        const now = new Date();
        const options = {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false // Use 24-hour format
        };
        document.getElementById("currentTime").innerText = `Current Time: ${now.toLocaleTimeString('en-US', options)}`;
    }

    // Change Background Images Functionality
    const images = [
        'url("static/images/bak.png")',

    ];

    let currentIndex = 0;

    function changeBackground() {
        document.body.style.backgroundImage = images[currentIndex];
        currentIndex = (currentIndex + 1) % images.length; // Cycle through images
    }

    // Update time every second
    setInterval(updateTime, 1000);
    updateTime(); // Initialize the time display immediately

    // Change image every 5 seconds
    setInterval(changeBackground, 5000);
});



// ==============================
// Base.html modals Functionality
// ==============================
    // Script to set the current year in the copyright
    document.getElementById('current-year').textContent = new Date().getFullYear();

    // Modal functionality
    const privacyModal = document.getElementById("privacy-modal");
    const termsModal = document.getElementById("terms-modal");
    const servicesModal = document.getElementById("services-modal");
    const contactModal = document.getElementById("contact-modal");

    document.getElementById("privacy-policy-link").onclick = function() {
        privacyModal.style.display = "block";
    }

    document.getElementById("terms-of-service-link").onclick = function() {
        termsModal.style.display = "block";
    }

    // Close modals using click events
    document.getElementById("close-privacy-modal").onclick = function() {
        privacyModal.style.display = "none";
    }

    document.getElementById("close-terms-modal").onclick = function() {
        termsModal.style.display = "none";
    }

    // Open the Services modal
    document.getElementById("services-link").onclick = function() {
        servicesModal.style.display = "block";
    };

    // Open the Contact Us modal
    document.getElementById("contact-link").onclick = function() {
        contactModal.style.display = "block";
    };

    // Close modals when clicking outside of them
    window.onclick = function(event) {
        if (event.target == privacyModal) {
            privacyModal.style.display = "none";
        }
        if (event.target == termsModal) {
            termsModal.style.display = "none";
        }
        if (event.target == servicesModal) {
            servicesModal.style.display = "none";
        }
        if (event.target == contactModal) {
            contactModal.style.display = "none";
        }
    }

    // Close Services modal
    document.getElementById("close-services").onclick = function() {
        servicesModal.style.display = "none";
    }

    // Close Contact modal
    document.getElementById("close-contact").onclick = function() {
        contactModal.style.display = "none";
    }

    // Close buttons on modals
    document.getElementById("close-services-btn").onclick = function() {
        servicesModal.style.display = "none";
    }

    document.getElementById("close-contact-btn").onclick = function() {
        contactModal.style.display = "none";
    }



// ==============================
// Create_Profile.html Tel Functionality
// ==============================

        // Initialize the phone input with country dropdown
        var input = document.querySelector("#phone_number");
        var iti = window.intlTelInput(input, {
            initialCountry: "auto",
            geoIpLookup: function(success, failure) {
                fetch("https://ipinfo.io/json?token=<YOUR_TOKEN_HERE>")
                    .then((resp) => resp.json())
                    .then((resp) => success(resp.country))
                    .catch(() => success("us"));
            },
            utilsScript: "https://cdnjs.cloudflare.com/ajax/libs/intl-tel-input/17.0.8/js/utils.js",
        });
    
        // When the form is submitted, store the full phone number in the hidden input
        document.querySelector("form").addEventListener("submit", function() {
            input.value = iti.getNumber();
        });



// ==============================
// Eye Functionality
// ==============================

        document.getElementById('togglePassword').addEventListener('click', function () {
            const passwordField = document.getElementById('password');
            const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordField.setAttribute('type', type);
            this.classList.toggle('fa-eye-slash');
        });
    
        document.getElementById('toggleConfirmPassword').addEventListener('click', function () {
            const confirmPasswordField = document.getElementById('confirm_password');
            const type = confirmPasswordField.getAttribute('type') === 'password' ? 'text' : 'password';
            confirmPasswordField.setAttribute('type', type);
            this.classList.toggle('fa-eye-slash');
        });