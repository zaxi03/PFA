(function ($) {
    "use strict";

    var trafficChart = null;
    var doughnutChart = null;

    // Spinner
    var spinner = function () {
        setTimeout(function () {
            if ($('#spinner').length > 0) {
                $('#spinner').removeClass('show');
            }
        }, 1);
    };
    spinner();

    // Back to top
    $(window).scroll(function () {
        if ($(this).scrollTop() > 300) {
            $('.back-to-top').fadeIn('slow');
        } else {
            $('.back-to-top').fadeOut('slow');
        }
    });
    $('.back-to-top').click(function () {
        $('html, body').animate({ scrollTop: 0 }, 1500, 'easeInOutExpo');
        return false;
    });

    // Sidebar Toggler
    $('.sidebar-toggler').click(function () {
        $('.sidebar, .content').toggleClass("open");
        return false;
    });

    // Chart style global
    Chart.defaults.color = "#6C7293";
    Chart.defaults.borderColor = "#000000";

    // Animation compteur
    function animateValue(id, start, end, duration) {
        const el = document.getElementById(id);
        let startTime = null;

        const step = (timestamp) => {
            if (!startTime) startTime = timestamp;
            const progress = Math.min((timestamp - startTime) / duration, 1);
            el.innerText = Math.floor(progress * (end - start) + start);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }

    // DOM Ready
    $(document).ready(function () {

        // --- TRAFIC AUTORISÉ / BLOQUÉ ---
        const salseRevenueCanvas = document.getElementById("salse-revenue");
        if (salseRevenueCanvas) {
            const salseRevenueCtx = salseRevenueCanvas.getContext("2d");

            fetch("/api/traffics/hourly")
                .then(response => response.json())
                .then(data => {
                    if (trafficChart) trafficChart.destroy();

                    trafficChart = new Chart(salseRevenueCtx, {
                        type: "line",
                        data: {
                            labels: data.hours,
                            datasets: [
                                {
                                    label: "Trafic autorisé",
                                    data: data.authorized,
                                    borderColor: "rgb(75, 192, 192)",
                                    fill: false,
                                    tension: 0.4
                                },
                                {
                                    label: "Trafic bloqué",
                                    data: data.blocked,
                                    borderColor: "rgb(255, 99, 132)",
                                    fill: false,
                                    tension: 0.4
                                }
                            ]
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                legend: { labels: { color: "#fff" } }
                            },
                            scales: {
                                x: {
                                    title: { display: true, text: "Heure", color: "#fff" },
                                    ticks: { color: "#fff" }
                                },
                                y: {
                                    beginAtZero: true,
                                    ticks: { color: "#fff" }
                                }
                            }
                        }
                    });

                    const totalAuthorized = data.authorized.reduce((a, b) => a + b, 0);
                    const totalBlocked = data.blocked.reduce((a, b) => a + b, 0);

                    animateValue("count-authorized", 0, totalAuthorized, 1000);
                    animateValue("count-blocked", 0, totalBlocked, 1000);
                })
                .catch(error => console.error("Erreur fetch trafic:", error));
        }

        // --- ATTAQUES FRÉQUENTES (Doughnut dynamique) ---
        const doughnutCanvas = document.getElementById("doughnut-chart");
        if (doughnutCanvas) {
            const doughnutCtx = doughnutCanvas.getContext("2d");

            fetch("/api/attacks/types")
                .then(res => res.json())
                .then(data => {
                    const labels = Object.keys(data);
                    const values = Object.values(data);
                    const colors = [
                        "rgba(255, 99, 132, 0.7)",
                        "rgba(54, 162, 235, 0.7)",
                        "rgba(255, 206, 86, 0.7)",
                        "rgba(75, 192, 192, 0.7)",
                        "rgba(153, 102, 255, 0.7)"
                    ];

                    if (doughnutChart) doughnutChart.destroy();

                    doughnutChart = new Chart(doughnutCtx, {
                        type: "doughnut",
                        data: {
                            labels: labels,
                            datasets: [{
                                label: "Types d'attaques",
                                data: values,
                                backgroundColor: colors.slice(0, labels.length),
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                legend: { labels: { color: "#fff" } }
                            }
                        }
                    });
                })
                .catch(err => console.error("Erreur doughnut-chart :", err));
        }

    });

})(jQuery);
