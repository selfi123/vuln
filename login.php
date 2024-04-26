<?php
$servername = "localhost";
$logname = "root";
$password = "";
$database = "vuln";

$conn = mysqli_connect($servername, $logname, $password, $database);

if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}


if (isset($_POST['register'])) {
    $logname = $_POST['logname'];
    $password = $_POST['regpass'];
    if (!preg_match('/^(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])/', $password)) {
        header("Location: /register?error=InvalidPassword");
        exit;
    }
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    $insertQuery = "INSERT INTO users (logname, password) VALUES ('$logname', '$hashedPassword')";

    if (mysqli_query($conn, $insertQuery)) {
        header("Location: /login?registration_success=1");
    } else {
        header("Location: /register?error=1");
    }
}
if (isset($_POST['login'])) {
    $logname = $_POST['logname'];
    $password = $_POST['logpass'];

    $selectQuery = "SELECT id, password FROM users WHERE logname = '$logname'";
    $result = mysqli_query($conn, $selectQuery);

    if ($result && mysqli_num_rows($result) == 1) {
        $row = mysqli_fetch_assoc($result);
        $hashedPassword = $row['password'];

        if (password_verify($password, $hashedPassword)) {
            session_start();
            $_SESSION['user_id'] = $row['id'];
            header("Location: /index1");
        } else {
            header("Location: /login?error=1");
        }
    } else {
        header("Location: /login?error=1");
    }}
mysqli_close($conn);
?>
