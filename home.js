<!DOCTYPE html>
<html>
<head>
    <title>Serveur</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <style>
        .background-image {
            background-image: url('https://kinsta.com/fr/wp-content/uploads/sites/4/2022/05/what-is-web-hosting-1-1024x512.jpg');
            background-size: cover;
            background-position: center;
            filter: blur(5px);
            width: 100%;
            height: 100%;
            color: white;
        }
    </style>
</head>
<body>
<nav class="navbar navbar-dark sticky-top bg-dark flex-md-nowrap p-2">
    <a class="navbar-brand px-5" href="#">Serveur</a>
    <ul class="navbar-nav px-3">
        <li class="nav-item text-nowrap">
            <a class="nav-link" href="#">Connexion</a>
        </li>
    </ul>
</nav>

<div class="container-fluid">
    <div class="row">
        <nav class="col-md-2 d-none d-md-block bg-light sidebar min-vh-100">
            <div class="sidebar-sticky">
                <ul class="nav flex-column">
                    <li class="nav-item">
                        <a class="nav-link active m-2" href="#">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-home"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
                            Dashboard
                        </a>
                    </li>
                </ul>
            </div>
        </nav>

        <main role="main" class="col-md-9 ml-sm-auto col-lg-10 pt-3 px-4">
            <div style="position: absolute; inset: 0px; overflow: hidden; pointer-events: none; visibility: hidden; z-index: -1;" class="background-image"></div>
            <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pb-2 mb-3 border-bottom">
                <h1 class="h2">Dashboard</h1>
            </div>
            <div class="col-12">
                <p class="d-flex">Statut du serveur : <span class="px-2 text-primary" id="status"></span></p>
                <button class="btn btn-primary mt-3" onclick="startWakeOnLan()">Démarrer le serveur</button>
                <p><span id="loading"></span></p>
            </div>
        </main>
    </div>
</div>

<script>
    window.onload = function () {
        // Afficher l'icône de chargement
        document.getElementById('status').innerHTML = "<span class='text-danger'>Serveur éteint</span>";

        // Effectuer l'appel à l'API pour obtenir le statut
        fetch('http://2.11.142.245:3000/server/status')
            .then(response => response.json())
            .then(data => {
                if (data.status === 1) {
                    // Si l'API renvoie 1, le serveur est allumé
                    document.getElementById('status').innerHTML = "<span class='text-success'>Serveur en fonctionnement</span>";
                } else {
                    document.getElementById('status').innerHTML = "<span class='text-danger'>Serveur éteint</span>";
                }
            })
            .catch(error => {
                console.error('Erreur :', error);
                document.getElementById('status').innerHTML = "<span class='text-danger'>Serveur éteint</span>";
            });
    };

    function startWakeOnLan() {
        document.getElementById('status').innerHTML = '<div class="d-flex"><p>Chargement</p><div class="spinner-border text-primary mx-3" role="status"><span class="visually-hidden">Loading...</span></div></div>';
        WakeOnLan()
        // Effectuer l'appel à l'API
        fetch('http://2.11.142.245:3000/server/status')
            .then(response => response.json())
            .then(data => {
                if (data.status === 1) {
                    // Si l'API renvoie 1, le serveur est allumé
                    document.getElementById('status').innerHTML = "<span class='text-success'>Serveur en fonctionnement</span>";
                } else {
                    // Si l'API renvoie autre chose que 1, le serveur est éteint
                    document.getElementById('status').innerHTML = "<span class='text-danger'>Serveur éteint</span>";
                }
            })
            .catch(error => {
                console.error('Erreur :', error);
                document.getElementById('status').innerHTML = "<span class='text-danger'>Serveur éteint</span>";
            });
    }


    function WakeOnLan() {

        // Effectuer l'appel à votre fichier PHP pour exécuter la fonction wakeOnLan
        $.ajax({
            type: "POST",
            url: "wol_fonction.php", // Utilisez le nom de votre fichier PHP
            data: {
                mac: '88:d7:f6:50:eb:b4',
                ip: '2.11.142.245',
                cidr: '24',
                port: '7'
            },
            success: function(response) {
            }
        });
    }
</script>

</body>
</html>
