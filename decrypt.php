<html>
<head>
    <title>Formulaire AES</title>
    <link rel="stylesheet" type="text/css" href="styleDecrypt.css">
</head>
<body>
    <nav>
       <ul>
           <li><a href="encrypt.php">Encrypt AES</a></li>
           <li><a href="decrypt.php">Decrypt AES</a></li>
       </ul>
    </nav>
    <header>
        <h1>Déchiffrement AES</h1>
    </header>
    <div class="main-content">
        <form action="decrypt.php" method="post">
            Texte à chiffrer : <input type="text" name="input1" required><br>
            Clé : <input type="text" name="input2" required><br>
            <input type="submit" value="Soumettre">
        </form>
        <?php
            if ($_SERVER['REQUEST_METHOD'] == 'POST') {
                $input1 = $_POST['input1'];
                $input2 = $_POST['input2'];

                exec('python AESEncrypt.py ' . escapeshellarg($input1) . ' ' . escapeshellarg($input2), $output);

                // Vérifier si la sortie existe et l'afficher
                if (isset($output[0])) {
                    echo htmlspecialchars($output[0]) . "</p>";
                    echo htmlspecialchars($output[1]) . "</p>";
                } else {
                    echo "<p>Erreur lors de l'exécution de la fonction AESEncrypt.py.</p>";
                }
            }
        ?>
    </div>
</body>
</html>



