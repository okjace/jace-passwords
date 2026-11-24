package com.okjace.jacepasswords.autofill

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import com.okjace.jacepasswords.JpApp

/** Android's autofill: called when any app or browser shows a sign-in form. */
class JpAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, signal: CancellationSignal, callback: FillCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: return callback.onSuccess(null)
        val f = Fields.parse(structure)
        if (f.isEmpty || f.pkg == packageName) return callback.onSuccess(null)
        val app = JpApp.app
        if (!app.vault.exists()) return callback.onSuccess(null)
        app.checkAutoLock()
        if (!app.vault.unlocked && app.vault.remembered()) runCatching { app.unlock(null, null) } // opens without a password here
        callback.onSuccess(if (app.vault.unlocked) Suggest.response(this, f) else Suggest.locked(this, f))
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: return callback.onSuccess()
        val f = Fields.parse(structure)
        if (f.passwordValue.isNullOrEmpty()) return callback.onSuccess()
        val app = JpApp.app
        if (app.vault.unlocked) {
            runCatching { Suggest.save(f) }
            callback.onSuccess()
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) { // unlock first, then save
            val i = Intent(this, AutofillActivity::class.java).putExtra(AutofillActivity.EXTRA_REQUEST, Request.of("save", f))
            callback.onSuccess(PendingIntent.getActivity(this, 3, i, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE).intentSender)
        } else callback.onSuccess()
    }
}
