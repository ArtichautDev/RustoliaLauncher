/**
 * Script for welcome.ejs
 */
document.getElementById('welcomeButton').addEventListener('click', e => {
    loginCancelEnabled(false) // False by default, be explicit.
    loginViewOnSuccess = VIEWS.landing
    loginViewOnCancel = VIEWS.welcome
    switchView(VIEWS.welcome, VIEWS.login)
})