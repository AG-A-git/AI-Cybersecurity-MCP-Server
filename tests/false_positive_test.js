function showMessage(username) {
    const message = "Hello " + username;
    console.log(message);
}

function safeText(username) {
    const output = document.getElementById("output");

    output.textContent = username;
}