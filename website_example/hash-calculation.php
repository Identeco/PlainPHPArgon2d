<!-- 
MIT License (c) 2023 Identeco
-->
<head>
<body>
<form action="hash-calculation.php" method="post">
    Message: <input type="text" name="message"> <br>
    Salt: <input type="text" name="salt" value="RandomSalt"> <br>
    Iterations: <input type="number" name="iterations" value="1"> <br>
    Memory KiB: <input type="number" name="memory" value="512"> <br>
    Parallelism: <input type="number" name="parallelism" value="1"> <br>
    Tag-length: <input type="number" name="tag-length" value="32"> <br>
    Version: <input type="number" name="version" value="19"> <br>
    Secret-Key: <input type="text" name="secret"> <br>
    Associated-Data: <input type="text" name="ad"> <br>
    <input type="submit"> <br>
</form>
<?php
    // Include the class for the Argon2d calculation
    include_once "../PlainArgon2d.php";

    // Disables warning due to low cost parameters when calculating an Argon2d hash
    error_reporting(E_ALL & ~E_USER_NOTICE);

    // Initialise Argon2d object
    $argon2 = new PlainArgon2d();

    if (isset($_POST["message"]) && $_POST["message"]!="" && $_POST["salt"]!="" && $_POST["iterations"]!="" && $_POST["memory"]!="" && $_POST["parallelism"]!=""&& $_POST["parallelism"]!=""&& $_POST["version"]!=""){
        
        $tstart = microtime(true);
        try {
            
            // Calculate the Argon2d hash of the username with a static salt and given cost parameters 
            $hash= $argon2->argon2d_raw_hash($_POST["message"], $_POST["salt"],(int) $_POST["memory"],(int) $_POST["iterations"],(int) $_POST["parallelism"],(int) $_POST["tag-length"],(int) $_POST["version"], $_POST["secret"], $_POST["ad"]);

        } catch (Exception $e) {
            echo("The following error occurred during the calculation: " .  $e->getMessage() . "<br>");
            exit(0);
        }
        $tdauer = microtime(true) - $tstart;
        echo("Calculation time: ".number_format((($tdauer) * 1000), 2). " ms <br>");
        echo("Memory consumption: ". number_format(memory_get_peak_usage()/1024/1024,2) . " MiB <br>");
        echo("Hash: ". bin2hex($hash));
    }
    else{
        echo("Please fill in all parameters for the calculation of an Argon2d hash!\n");
    }
?>
</body>
</head>
