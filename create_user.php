<?php
// Set your valid API key (from osTicket admin panel under Manage -> API Keys)
$valid_api_key = '0634BF8B458FDAC91812020ADD2AED89'; // Replace with your actual API key

// Get the API key from the headers
$headers = getallheaders();
$api_key = $headers['API_KEY'] ?? null;  // Use getallheaders() to get the API key

// Validate the API key
if ($api_key !== $valid_api_key) {
    // Invalid API key, return an error response
    echo json_encode(['error' => 'Invalid API key']);
    exit;
}

// Database connection details
$servername = "localhost";  // Or your DB host
$username = "osticket";  // Replace with your DB username
$password = "osticket";  // Replace with your DB password
$dbname = "12345678";  // Replace with your osTicket DB name

// Check if the request method is POST and parameters are provided
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get the user details from the POST request
    $email = $_POST['email'] ?? null;
    $name = $_POST['name'] ?? null;
    $password = $_POST['password'] ?? null;

    // Ensure required fields are present
    if ($email && $name && $password) {
        try {
            // Create a new PDO database connection
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Prepare an SQL query to insert the new user into the `ost_user` table
            $stmt = $conn->prepare("
                INSERT INTO ost_user (name, email, passwd)
                VALUES (:name, :email, :password)
            ");
            
            // Bind parameters to the SQL query and hash the password using BCRYPT
            $stmt->bindParam(':name', $name);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':password', password_hash($password, PASSWORD_BCRYPT));

            // Execute the SQL query
            if ($stmt->execute()) {
                // Success: User created
                echo json_encode(['success' => true, 'message' => 'User created successfully']);
            } else {
                // Failure: Could not create user
                echo json_encode(['success' => false, 'message' => 'Failed to create user']);
            }
        } catch (PDOException $e) {
            // Handle any database connection or query errors
            echo json_encode(['error' => 'Connection failed: ' . $e->getMessage()]);
        }
    } else {
        // Error: Missing parameters
        echo json_encode(['error' => 'Missing parameters: name, email, or password']);
    }
} else {
    // Error: Invalid request method
    echo json_encode(['error' => 'Invalid request method. Please use POST.']);
}
?>