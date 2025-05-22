(function ($) {
    "use strict";

    // Spinner
    var spinner = function () {
        setTimeout(function () {
            if ($('#spinner').length > 0) {
                $('#spinner').removeClass('show');
            }
        }, 1);
    };
    spinner();

    // Back to top button
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

    // Chart Global Color
    Chart.defaults.color = "#6C7293";
    Chart.defaults.borderColor = "#000000";

    // Attendre que le DOM soit prêt
    $(document).ready(function () {
        // Trafic autorisé vs bloqué (Line Chart)
        const salseRevenueCanvas = document.getElementById("salse-revenue");
        if (salseRevenueCanvas) {
            const salseRevenueCtx = salseRevenueCanvas.getContext("2d");
            new Chart(salseRevenueCtx, {
                type: "line",
                data: {
                    labels: ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
                    datasets: [
                        {
                            label: "Trafic autorisé",
                            data: [120, 190, 300, 250, 220, 300],
                            borderColor: "rgb(75, 192, 192)",
                            fill: false,
                            tension: 0.4
                        },
                        {
                            label: "Trafic bloqué",
                            data: [60, 80, 200, 150, 180, 160],
                            borderColor: "rgb(255, 99, 132)",
                            fill: false,
                            tension: 0.4
                        }
                    ]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            labels: { color: "#fff" }
                        }
                    }
                }
            });
        }

        // Attaques fréquentes (Doughnut Chart)
        const doughnutCanvas = document.getElementById("doughnut-chart");
        if (doughnutCanvas) {
            const doughnutCtx = doughnutCanvas.getContext("2d");
            new Chart(doughnutCtx, {
                type: "doughnut",
                data: {
                    labels: ["SQLi", "XSS", "BruteForce"],
                    datasets: [{
                        label: "Types d'attaques",
                        data: [40, 25, 35],
                        backgroundColor: [
                            "rgba(255, 99, 132, 0.7)",
                            "rgba(54, 162, 235, 0.7)",
                            "rgba(255, 206, 86, 0.7)"
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            labels: { color: "#fff" }
                        }
                    }
                }
            });
        }
    });

})(jQuery);
