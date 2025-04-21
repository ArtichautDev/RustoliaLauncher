/**
 * AuthManager
 * 
 * This module aims to abstract login procedures. Results from Mojang's REST api
 * are retrieved through our Mojang module. These results are processed and stored,
 * if applicable, in the config using the ConfigManager. All login procedures should
 * be made through this module.
 * 
 * @module authmanager
 */
// Requirements
const ConfigManager          = require('./configmanager')
const { LoggerUtil }         = require('helios-core')
const { RestResponseStatus } = require('helios-core/common')
const { MojangRestAPI } = require('helios-core/mojang')  // used for logout
const { AuthClient } = require('azuriom-auth')
const Lang = require('./langloader')

const log = LoggerUtil.getLogger('AuthManager')

// Error messages

function mojangErrorDisplayable(errorCode) {
    switch(errorCode) {
        case MojangErrorCode.ERROR_METHOD_NOT_ALLOWED:
            return {
                title: Lang.queryJS('auth.mojang.error.methodNotAllowedTitle'),
                desc: Lang.queryJS('auth.mojang.error.methodNotAllowedDesc')
            }
        case MojangErrorCode.ERROR_NOT_FOUND:
            return {
                title: Lang.queryJS('auth.mojang.error.notFoundTitle'),
                desc: Lang.queryJS('auth.mojang.error.notFoundDesc')
            }
        case MojangErrorCode.ERROR_USER_MIGRATED:
            return {
                title: Lang.queryJS('auth.mojang.error.accountMigratedTitle'),
                desc: Lang.queryJS('auth.mojang.error.accountMigratedDesc')
            }
        case MojangErrorCode.ERROR_INVALID_CREDENTIALS:
            return {
                title: Lang.queryJS('auth.mojang.error.invalidCredentialsTitle'),
                desc: Lang.queryJS('auth.mojang.error.invalidCredentialsDesc')
            }
        case MojangErrorCode.ERROR_RATELIMIT:
            return {
                title: Lang.queryJS('auth.mojang.error.tooManyAttemptsTitle'),
                desc: Lang.queryJS('auth.mojang.error.tooManyAttemptsDesc')
            }
        case MojangErrorCode.ERROR_INVALID_TOKEN:
            return {
                title: Lang.queryJS('auth.mojang.error.invalidTokenTitle'),
                desc: Lang.queryJS('auth.mojang.error.invalidTokenDesc')
            }
        case MojangErrorCode.ERROR_ACCESS_TOKEN_HAS_PROFILE:
            return {
                title: Lang.queryJS('auth.mojang.error.tokenHasProfileTitle'),
                desc: Lang.queryJS('auth.mojang.error.tokenHasProfileDesc')
            }
        case MojangErrorCode.ERROR_CREDENTIALS_MISSING:
            return {
                title: Lang.queryJS('auth.mojang.error.credentialsMissingTitle'),
                desc: Lang.queryJS('auth.mojang.error.credentialsMissingDesc')
            }
        case MojangErrorCode.ERROR_INVALID_SALT_VERSION:
            return {
                title: Lang.queryJS('auth.mojang.error.invalidSaltVersionTitle'),
                desc: Lang.queryJS('auth.mojang.error.invalidSaltVersionDesc')
            }
        case MojangErrorCode.ERROR_UNSUPPORTED_MEDIA_TYPE:
            return {
                title: Lang.queryJS('auth.mojang.error.unsupportedMediaTypeTitle'),
                desc: Lang.queryJS('auth.mojang.error.unsupportedMediaTypeDesc')
            }
        case MojangErrorCode.ERROR_GONE:
            return {
                title: Lang.queryJS('auth.mojang.error.accountGoneTitle'),
                desc: Lang.queryJS('auth.mojang.error.accountGoneDesc')
            }
        case MojangErrorCode.ERROR_UNREACHABLE:
            return {
                title: Lang.queryJS('auth.mojang.error.unreachableTitle'),
                desc: Lang.queryJS('auth.mojang.error.unreachableDesc')
            }
        case MojangErrorCode.ERROR_NOT_PAID:
            return {
                title: Lang.queryJS('auth.mojang.error.gameNotPurchasedTitle'),
                desc: Lang.queryJS('auth.mojang.error.gameNotPurchasedDesc')
            }
        case MojangErrorCode.UNKNOWN:
            return {
                title: Lang.queryJS('auth.mojang.error.unknownErrorTitle'),
                desc: Lang.queryJS('auth.mojang.error.unknownErrorDesc')
            }
        default:
            throw new Error(`Unknown error code: ${errorCode}`)
    }
}

// Functions

/**
 * Authenticate via Azuriom Auth.
 * @param {string} email
 * @param {string} password
 * @param {string|null} twoFaCode optional 2FA code
 * @returns {Promise<Object>} resolved account via ConfigManager
 */
exports.addMojangAccount = async function(email, password, twoFaCode = null) {
    try {
        const client = new AuthClient('https://rustolia.eu')
        let result = await client.login(email, password, twoFaCode)
        if (result.status === 'pending' && result.requires2fa) {
            return Promise.reject({ requires2fa: true })
        }
        if (result.status !== 'success') {
            return Promise.reject({ title: Lang.queryJS('login.error.unknown'), desc: JSON.stringify(result) })
        }
        // Extract user ID and UUID
        const userId = result.id ? String(result.id) : null
        const uuid = result.uuid || (userId != null ? userId : email)
        const displayName = result.username || email
        const accessToken = result.token || result.accessToken || result.access_token
        
        // Store userId as part of the account data for token generation
        const ret = ConfigManager.addMojangAuthAccount(uuid, accessToken, email, displayName, userId)
        ConfigManager.save()
        return ret
    } catch(err) {
        log.error('AZAuth login error', err)
        return Promise.reject({ title: Lang.queryJS('login.error.unknown'), desc: err.toString() })
    }
}

/**
 * Remove a Mojang account. This will invalidate the access token associated
 * with the account and then remove it from the database.
 * 
 * @param {string} uuid The UUID of the account to be removed.
 * @returns {Promise.<void>} Promise which resolves to void when the action is complete.
 */
exports.removeMojangAccount = async function(uuid){
    try {
        const authAcc = ConfigManager.getAuthAccount(uuid)
        const response = await MojangRestAPI.invalidate(authAcc.accessToken, ConfigManager.getClientToken())
        if(response.responseStatus === RestResponseStatus.SUCCESS) {
            ConfigManager.removeAuthAccount(uuid)
            ConfigManager.save()
            return Promise.resolve()
        } else {
            log.error('Error while removing account', response.error)
            return Promise.reject(response.error)
        }
    } catch (err){
        log.error('Error while removing account', err)
        return Promise.reject(err)
    }
}

/**
 * Validate the selected auth account.
 * 
 * @returns {Promise.<boolean>} Promise which resolves to true if the access token is valid,
 * otherwise false.
 */
exports.validateSelected = async function(){
    const current = ConfigManager.getSelectedAccount()

    if(current.type === 'microsoft') {
        // Microsoft accounts are no longer supported
        return false
    } else {
        // Mojang accounts are now handled by Azuriom Auth
        // We can't validate the account, so just return true
        return true
    }
    
}

/**
 * Remove a Microsoft account. It is expected that the caller will invoke the OAuth logout
 * through the ipc renderer.
 * 
 * @param {string} uuid The UUID of the account to be removed.
 * @returns {Promise.<void>} Promise which resolves to void when the action is complete.
 */
exports.removeMicrosoftAccount = async function(uuid){
    try {
        ConfigManager.removeAuthAccount(uuid)
        ConfigManager.save()
        return Promise.resolve()
    } catch (err){
        log.error('Error while removing account', err)
        return Promise.reject(err)
    }
}

/**
 * Logout from Azuriom Auth and invalidate the access token, then remove the account.
 * This follows the same pattern as removeMojangAccount.
 * 
 * @param {string} uuid The UUID of the account to be removed.
 * @returns {Promise.<void>} Promise which resolves to void when the action is complete.
 */
exports.logout = async function(uuid){
    try {
        const authAcc = ConfigManager.getAuthAccount(uuid)
        
        if (authAcc && authAcc.accessToken) {
            const client = new AuthClient('https://rustolia.eu')
            const response = await client.logout(authAcc.accessToken)
            
            if (response && response.status === 'success') {
                // Si la déconnexion est réussie, supprimer le compte
                ConfigManager.removeAuthAccount(uuid)
                ConfigManager.save()
                return Promise.resolve()
            } else {
                log.error('Error during Azuriom Auth logout', response)
                // En cas d'erreur, on continue et on supprime quand même le compte localement
                // car l'API peut renvoyer des erreurs si le token est déjà invalide
                ConfigManager.removeAuthAccount(uuid)
                ConfigManager.save()
                return Promise.resolve()
            }
        } else {
            // Si pas de token, on supprime juste le compte
            ConfigManager.removeAuthAccount(uuid)
            ConfigManager.save()
            return Promise.resolve()
        }
    } catch (err) {
        log.error('Error during Azuriom Auth logout', err)
        // En cas d'erreur, on supprime quand même le compte localement
        // pour éviter que l'utilisateur ne reste bloqué
        try {
            ConfigManager.removeAuthAccount(uuid)
            ConfigManager.save()
        } catch (innerErr) {
            log.error('Error removing account after logout failure', innerErr)
        }
        return Promise.resolve() // On continue même en cas d'erreur
    }
}
