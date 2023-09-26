<html>
<?php
echo "achan123";
session_start();
$host = "localhost";
$username = "root";
$password = "";
$database = "vuln";

$connection = mysqli_connect($host, $username, $password, $database);

if (isset($_POST['logname']) && isset($_POST['logpass'])) {
    $username = $_POST['logname'];
    $password = $_POST['logpass'];
    

    $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    $result = mysqli_query($connection, $query);

    if (mysqli_num_rows($result) == 1) {
        $_SESSION['username'] = $username;
        header("Location: index1");
    } else {
        echo "Invalid username or password.";
    }


    
}

?>
</html>