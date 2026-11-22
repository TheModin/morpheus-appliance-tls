package io.github.themodin.morpheus.tls

import com.morpheusdata.core.AbstractGlobalUIComponentProvider
import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.core.Plugin
import com.morpheusdata.model.Account
import com.morpheusdata.model.User
import com.morpheusdata.views.HTMLResponse
import com.morpheusdata.views.ViewModel

/** Small status link to the admin page on every page; hidden client-side for users without access. */
class BadgeProvider extends AbstractGlobalUIComponentProvider {
    Plugin plugin
    MorpheusContext morpheus
    String code = 'tls-badge'
    String name = "TLS certificate badge"

    BadgeProvider(Plugin plugin, MorpheusContext morpheus) { this.plugin = plugin; this.morpheus = morpheus }

    /**
     * User.permissions maps a plugin permission code to the user's highest access type (see User#getPermissions).
     * The badge script additionally hides itself unless the admin API answers.
     */
    @Override
    Boolean show(User user, Account account) {
        return 'full' == user?.permissions?.get('tlsApplianceCert')
    }

    @Override
    HTMLResponse renderTemplate(User user, Account account) {
        ViewModel<User> model = new ViewModel<>()
        model.object = user
        getRenderer().renderTemplate('hbs/badge', model)
    }
}
