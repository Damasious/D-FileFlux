document.getElementById('login-form').addEventListener('submit', function(event) {
    event.preventDefault();
    const email = document.getElementById('email-input').value;
    const password = document.getElementById('password-input').value;

    const formData = new FormData();
    formData.append('email', email);
    formData.append('password', password);

    fetch('/', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.ok) {
            window.location.href = '/home';
        } else {
            document.getElementById('login-status').innerText = 'Login Failed. Please check username and password.';
        }
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('login-status').innerText = 'An error occurred. Please try again.';
    });
});

// Função para animar o título
function animateTitle() {
    const title = document.getElementById('animated-title');
    title.style.width = '100%'; // Inicia a animação do título
}

window.onload = animateTitle;
