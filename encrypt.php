<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Encrypt AES</title>
    <link rel="stylesheet" type="text/css" href="styleEncrypt.css">
</head>
<body>
    <nav>
        <ul>
            <li><a href="encrypt.php">Encrypt AES</a></li>
            <li><a href="decrypt.php">Decrypt AES</a></li>
        </ul>
    </nav>
    <header>
        <h1>Chiffrement AES</h1>
    </header>

    <div class="main-content">
        <form action="encrypt.php" method="post">
            <label for="input1">Texte à chiffrer :</label>
            <input type="text" id="input1" name="input1" required><br><br>

            <label>Choisissez la longueur de la clé :</label><br>
            <input type="radio" id="key128" name="key_length" value="128" checked>
            <label for="key128">128 bits</label><br>
            <input type="radio" id="key192" name="key_length" value="192">
            <label for="key192">192 bits</label><br>
            <input type="radio" id="key256" name="key_length" value="256">
            <label for="key256">256 bits</label><br><br>

            <input type="submit" value="Soumettre" class="blink">
        </form>

        <?php
            if ($_SERVER['REQUEST_METHOD'] == 'POST') {
                $input1 = $_POST['input1'];
                $key_length = $_POST['key_length'];

                exec('python AESEncrypt.py ' . escapeshellarg($input1) . ' ' . escapeshellarg($key_length), $output);

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

