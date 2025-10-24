let currentMode = 'encryot';

const elements = {
    encryptBtn: document.getElementById('encryptBtn'),
    decryptBtn: document.getElementById('decryptBtn'),
    encryptForm: document.getElementById('encryptForm'),
    inputText: document.getElementById('inputText'),
    password: document.getElementById('password'),
    submitBtn: document.getElementById('submitBtn'),
    clearBtn: document.getElementById('clearBtn'),
}

function setMode(mode) {
    currentMode = mode;

    if (mode === 'encrypt') {
        elements.encryptBtn.classList.add('active');
        elements.decryptBtn.classList.remove('active');
    } else {
        elements.decryptBtn.classList.add('active');
        elements.encryptBtn.classList.remove('active');
    }

    clearForm()

}

function showAlert(message, type) {

}

function clearForm() {
    elements.inputText.value = '';
    elements.password.value = '';
}