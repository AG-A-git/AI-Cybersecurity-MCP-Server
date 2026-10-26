const userInput = location.search;
document.body.innerHTML = userInput;


function displayUserInput() {
    const input = document.getElementById("username").value;

    document.getElementById("output").innerHTML = input;
}