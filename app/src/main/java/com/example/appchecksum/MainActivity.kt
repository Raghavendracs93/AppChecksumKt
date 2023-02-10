package com.example.appchecksum

import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.example.appchecksum.AppSignatureHelper.Companion.hash
import com.example.appchecksum.ui.theme.AppChecksumTheme
import java.io.FileInputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.Arrays


class MainActivity : ComponentActivity() {
    @RequiresApi(Build.VERSION_CODES.P)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            AppChecksumTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {

                    val packageName = applicationContext.packageName
                    val pm = applicationContext.packageManager
                    val ai = pm.getApplicationInfo(packageName, 0)
                    val srcDir = ai.publicSourceDir

                    Greeting("Raaghu")
                    hash(applicationContext.packageName,"signature");
//                    getApkName(applicationContext)
                    verifier(context = applicationContext)
                    check(applicationContext)
                    val sign = getAppSignature()
                    Log.d("sign", sign.toString())
                    fileIntegrity(applicationContext,srcDir, "dir")
                    fileIntegrity(applicationContext,sign.toString(),"sig")
                    checkSignatures(srcDir)
                }
            }
        }

    }

    private fun checkSignatures(srcDir: String) {
        Log.d("srcDir", srcDir.toString())
        val sig: Signature = applicationContext.getPackageManager()
            .getPackageInfo(applicationContext.getPackageName(), PackageManager.GET_SIGNATURES).signatures.get(
                0
            )
        val releaseSig: Signature = applicationContext.getPackageManager().getPackageArchiveInfo(
            srcDir,
            PackageManager.GET_SIGNATURES
        )!!.signatures[0]

        Log.d("checkSignatures", sig.hashCode().toString() + " , "  +  releaseSig.hashCode().toString())

        if(sig.hashCode().toString() == releaseSig.hashCode().toString() ){
            Log.d("signs", "iffffff")
        } else Log.d("signs", "elseeeeeee")

    }

    fun check(context: Context?){
        val sig: android.content.pm.Signature? =
            context!!.packageManager.getPackageInfo(
                context!!.packageName,
                PackageManager.GET_SIGNATURES
            ).signatures[0]
        Log.d("sig", sig.toString())



    }

    private fun fileIntegrity(context: Context, string: String, type: String) {
        try {

            val digest: MessageDigest = MessageDigest.getInstance("SHA-256")

            if(type == "dir"){
                val input: InputStream = FileInputStream(string)
                val hash: ByteArray = digest.digest(input.readBytes())
                hash.toHexString()
                Log.d("dir hash ", hash.toString())
                Log.d("dir hash hex  ", hash.toHexString())
            }else{
                val hash = digest.digest(string.toByteArray())
                Base64.encodeToString(hash, Base64.NO_WRAP)
                Log.d("sign hash", hash.toString())
                Log.d("sign  hash hex", hash.toHexString())
            }

        }catch (exception : NoSuchAlgorithmException){
            exception.printStackTrace()
            null
        }
    }

    fun ByteArray.toHexString() : String{
        val hexChars = "0123456789ABCDEF".toCharArray()
        val result = StringBuffer()

        forEach {
            val octet = it.toInt()
            val firstIndex = (octet and 0xF0).ushr(4)
            val secondIndex = octet and 0x0F
            result.append(hexChars[firstIndex])
            result.append(hexChars[secondIndex])
        }

        return result.toString()

    }

    private fun Context.getAppSignature(): android.content.pm.Signature? = if (Build.VERSION.SDK_INT < 28) {
        packageManager.getPackageInfo(
            packageName,
            PackageManager.GET_SIGNATURES
        ).signatures.firstOrNull()
    } else {
        packageManager.getPackageInfo(
            packageName,
            PackageManager.GET_SIGNING_CERTIFICATES
        ).signingInfo.apkContentsSigners.firstOrNull()
    }

}


@RequiresApi(Build.VERSION_CODES.P)
fun verifier(context: Context) {
    val packageName = context.packageName
    val pm = context.packageManager
    val ai = pm.getApplicationInfo(packageName, 0)
    val srcDir = ai.publicSourceDir
    val sign =  pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures.firstOrNull();
    val releaseSig = context.packageManager.getPackageArchiveInfo(
        srcDir,
        PackageManager.GET_SIGNING_CERTIFICATES
    )?.signingInfo.hashCode()

    Log.d("verifier func", String.format("sign: %s -- releaseSign: %s", sign, releaseSig))


}
fun getApkName(context: Context): String? {
    val packageName = context.packageName
    val pm = context.packageManager
    try {
        val ai = pm.getApplicationInfo(packageName, 0)
        Log.d("dirrrrrrrrr", ai.toString())
        Log.d("dirrrrrrrrr", ai.publicSourceDir)
    } catch (x: Throwable) {
    }
    return null
}
fun getDirName(context: Context): String? {
    val packageName = context.packageName
    val pm = context.packageManager
    val ai = pm.getApplicationInfo(packageName, 0)

    return ai.publicSourceDir
}


/**
 * This is a helper class to generate your message hash to be included in your SMS message.
 *
 * Without the correct hash, your app won't recieve the message callback. This only needs to be
 * generated once per app and stored. Then you can remove this helper class from your code.
 */
class AppSignatureHelper(context: Context?) : ContextWrapper(context) {// Get all package signatures for the current package

    // For each signature create a compatible hash
    /**
     * Get all the app signatures for the current package
     * @return
     */

    val appSignatures: ArrayList<String>
        @RequiresApi(Build.VERSION_CODES.P)
        get() {
            val appCodes = ArrayList<String>()
            try {
                Log.d("App Sign", "APPPPPPPPPPPPPPPPPPP: ")
                // Get all package signatures for the current package
                val packageName = packageName
                val packageManager = packageManager
                val signatures = packageManager.getPackageInfo(packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES).signatures
//                packageManager.getPackageInfo(applicationContext.packageName)
                // For each signature create a compatible hash
                for (signature in signatures) {
                    val hash = hash(packageName, signature.toCharsString())
                    if (hash != null) {
                        appCodes.add(String.format("%s", hash))
                    }
                }
                Log.d("appCodes", appCodes.toString())
            } catch (e: PackageManager.NameNotFoundException) {
                Log.d(e.toString(), ":e, \"Unable to find package to obtain hash.\" ")
            }
            return appCodes
        }

    companion object {
        val TAG = AppSignatureHelper::class.java.simpleName
        private const val HASH_TYPE = "SHA-256"
        const val NUM_HASHED_BYTES = 9
        const val NUM_BASE64_CHAR = 11
         fun hash(packageName: String, signature: String): String? {
            val appInfo = "$packageName $signature"
            try {
                Log.d(TAG, "AppSignatureHelper: invoked ")
                val messageDigest = MessageDigest.getInstance(HASH_TYPE)
                messageDigest.update(appInfo.toByteArray(StandardCharsets.UTF_8))
                var hashSignature = messageDigest.digest()

                // truncated into NUM_HASHED_BYTES
                hashSignature = Arrays.copyOfRange(hashSignature, 0, NUM_HASHED_BYTES)
                // encode into Base64
                var base64Hash = Base64.encodeToString(hashSignature, Base64.NO_PADDING or Base64.NO_WRAP)
                base64Hash = base64Hash.substring(0, NUM_BASE64_CHAR)
                Log.d("pkg", String.format("pkg: %s -- hash: %s", packageName, base64Hash))
                return base64Hash
            } catch (e: NoSuchAlgorithmException) {
                Log.d(e.toString(), "hash:NoSuchAlgorithm")
            }
            return null
        }
    }
}



@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello $name!",
        modifier = modifier
    )
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    AppChecksumTheme {
        Greeting("Ramu")
    }
}