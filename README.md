# FingerScanDemo

Android 指纹识别例子


# Android指纹识别使用

## 本文内容

1.  指纹相关类

2. 指纹识别的兼容性检测

3. 对称加密和非对称加密使用方式


## 指纹相关类

android.hardware.fingerprint 包下

1. FingerprintManager：主要用来协调管理和访问指纹识别硬件设备
2. FingerprintManager.AuthenticationCallback这个一个callback接口，当指纹认证后系统会回调这个接口通知app认证的结果是什么
3. FingerprintManager.AuthenticationResult这是一个表示认证结果的类，会在回调接口中以参数给出
4. FingerprintManager.CryptoObject这是一个加密的对象类，用来保证认证的安全性，这是一个重点，下面我们会分析。

## 使用步骤

### 1.添加权限

```xml
<uses-permission android:name="android.permission.USE_FINGERPRINT"/>
```

### 2.获得FingerprintManager的对象引用

不同版本的获取方式：

```java
// Using the Android Support Library v4
fingerprintManager = FingerprintManagerCompat.from(this);

// Using API level 23:
fingerprintManager = (FingerprintManager)getSystemService(Context.FINGERPRINT_SERVICE);
```

### 3.在运行是检查设备指纹识别的兼容性

#### 1) API level 23

指纹识别API是在api level 23也就是android 6.0中加入的，因此我们的app必须运行在这个系统版本之上。因此google推荐使用 Android Support Library v4包来获得FingerprintManagerCompat对象，因为在获得的时候这个包会检查当前系统平台的版本。

#### 2) 硬件

指纹识别肯定要求你的设备上有指纹识别的硬件，因此在运行时需要检查系统当中是不是有指纹识别的硬件：

```java
fingerprintManager.isHardwareDetected()
```

#### 3) 当前设备必须开启屏幕锁

想要使用指纹识别的话，必须首先使能屏幕锁才行，这个和android 5.0中的smart lock逻辑是一样的，这是因为google认为目前的指纹识别技术还是有不足之处，安全性还是不能和传统的方式比较的。

```java
KeyguardManager keyguardManager =(KeyguardManager)getSystemService(Context.KEYGUARD_SERVICE);
if (keyguardManager.isKeyguardSecure()) {
// this device is secure.
}
```

#### 4) 系统中是不是有注册的指纹

在android 6.0中，普通app要想使用指纹识别功能的话，用户必须首先在setting中注册至少一个指纹才行，否则是不能使用的。

```java
fingerprintManager.hasEnrolledFingerprints()
```

### 扫描认证用户指纹

调用FingerprintManager的authenticate方法即可

```java
/**
* @param crypto object associated with the call or null if none required.
* @param flags optional flags; should be 0
* @param cancel an object that can be used to cancel authentication
* @param callback an object to receive authentication events
* @param handler an optional handler for events
*/
public void authenticate(CryptoObject crypto, int flags,CancellationSignal cancel, AuthenticationCallback callback, Handler handler) {
IMPL.authenticate(mContext, crypto, flags, cancel, callback, handler);
}
```

参数：

1. crypto 这是一个加密类的对象，指纹扫描器会使用这个对象来判断认证结果的合法性。这个对象可以是null，但是这样的话，就意味这app无条件信任认证的结果，虽然从理论上这个过程可能被攻击，数据可以被篡改，这是app在这种情况下必须承担的风险。因此，建议这个参数不要置为null。这个类的实例化有点麻烦，主要使用javax的security接口实现，后面我的demo程序中会给出一个helper类，这个类封装内部实现的逻辑，开发者可以直接使用我的类简化实例化的过程。

2. cancel 这个是CancellationSignal类的一个对象，这个对象用来在指纹识别器扫描用户指纹的是时候取消当前的扫描操作，如果不取消的话，那么指纹扫描器会移植扫描直到超时（一般为30s，取决于具体的厂商实现），这样的话就会比较耗电。建议这个参数不要置为null。

3. flags 标识位，根据上图的文档描述，这个位暂时应该为0，这个标志位应该是保留将来使用的。

4. callback 这个是FingerprintManager.AuthenticationCallback类的对象，这个是这个接口中除了第一个参数之外最重要的参数了。当系统完成了指纹认证过程（失败或者成功都会）后，会回调这个对象中的接口，通知app认证的结果。这个参数不能为NULL。

5. handler 这是Handler类的对象，如果这个参数不为null的话，那么FingerprintManager将会使用这个handler中的looper来处理来自指纹识别硬件的消息。通常来讲，开发这不用提供这个参数，可以直接置为null，因为FingerprintManager会默认使用app的main looper来处理。

### 其它操作

#### 取消扫描

使用CancellationSignal这个类的cancel方法

#### 第一种方式：创建CryptoObject类对象，使用对称加密实现指纹识别

对称加密方式：用于本地指纹验证使用
非对称加密方式：用于后台服务器指纹验证

FingerprintManager.CryptoObject是基于Java加密API的一个包装类，并且被FingerprintManager用来保证认证结果的完整性。

```java
public class CryptoObjectHelper {
// This can be key name you want. Should be unique for the app.
static final String KEY_NAME = "com.createchance.android.sample.fingerprint_authentication_key";
// We always use this keystore on Android.
static final String KEYSTORE_NAME = "AndroidKeyStore";
// Should be no need to change these values.
static final String KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES;
static final String BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC;
static final String ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7;
static final String TRANSFORMATION = KEY_ALGORITHM + "/" +
BLOCK_MODE + "/" +
ENCRYPTION_PADDING;
final KeyStore _keystore;
public CryptoObjectHelper() throws Exception {
_keystore = KeyStore.getInstance(KEYSTORE_NAME);
_keystore.load(null);
}
public FingerprintManagerCompat.CryptoObject buildCryptoObject() throws Exception {
Cipher cipher = createCipher(true);
return new FingerprintManagerCompat.CryptoObject(cipher);
}
Cipher createCipher(boolean retry) throws Exception {
Key key = GetKey();
Cipher cipher = Cipher.getInstance(TRANSFORMATION);
try {
cipher.init(Cipher.ENCRYPT_MODE | Cipher.DECRYPT_MODE, key);
} catch (KeyPermanentlyInvalidatedException e) {
_keystore.deleteEntry(KEY_NAME);
if (retry) {
createCipher(false);
} else {
throw new Exception("Could not create the cipher for fingerprint authentication.", e);
}
}
return cipher;
}
Key GetKey() throws Exception {
Key secretKey;
if (!_keystore.isKeyEntry(KEY_NAME)) {
CreateKey();
}
secretKey = _keystore.getKey(KEY_NAME, null);
return secretKey;
}
void CreateKey() throws Exception {
KeyGenerator keyGen = KeyGenerator.getInstance(KEY_ALGORITHM, KEYSTORE_NAME);
KeyGenParameterSpec keyGenSpec =
new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
.setBlockModes(BLOCK_MODE)
.setEncryptionPaddings(ENCRYPTION_PADDING)
.setUserAuthenticationRequired(true)
.build();
keyGen.init(keyGenSpec);
keyGen.generateKey();
}
}
```

上面的类会针对每个CryptoObject对象都会新建一个Cipher对象，并且会使用由应用生成的key。这个key的名字是使用KEY_NAME变量定义的，这个名字应该是保证唯一的，建议使用域名区别。

GetKey方法会尝试使用Android Keystore的API来解析一个key（名字就是上面我们定义的），如果key不存在的话，那就调用CreateKey方法新建一个key。

cipher变量的实例化是通过调用Cipher.getInstance方法获得的，这个方法接受一个transformation参数，这个参数制定了数据怎么加密和解密。然后调用Cipher.init方法就会使用应用的key来完成cipher对象的实例化工作。

这里需要强调一点，在以下情况下，android会认为当前key是无效的：

1. 一个新的指纹image已经注册到系统中
2. 当前设备中的曾经注册过的指纹现在不存在了，可能是被全部删除了
3. 用户关闭了屏幕锁功能
4. 用户改变了屏幕锁的方式

当上面的情况发生的时候，Cipher.init方法都会抛出KeyPermanentlyInvalidatedException的异常，上面我的代码中捕获了这个异常，并且删除了当前无效的key，然后根据参数尝试再次创建。

上面的代码中使用了android的KeyGenerator来创建一个key并且把它存储在设备中。KeyGenerator类会创建一个key，但是需要一些原始数据才能创建key，这些原始的信息是通过KeyGenParameterSpec类的对象来提供的。KeyGenerator类对象的实例化是使用它的工厂方法getInstance进行的，从上面的代码中我们可以看到这里使用AES（Advanced Encryption Standard ）加密算法，AES会将数据分成几个组，然后针对几个组进行加密。

接下来，KeyGenParameterSpec的实例化是使用它的Builder方法，KeyGenParameterSpec.Builder封装了以下重要的信息：

1. key的名字。
2. key必须在加密和解密的时候是有效的。
3. BLOCK_MODE被设置为KeyProperties.BLOCK_MODE_CBC，即AES算法使用CBC模式。
4. 使用PKSC7（Public Key Cryptography Standard #7）的方式去产生用于填充AES数据块的字节(也叫Padding)，这样就是要保证每个数据块的大小相同的。
5. setUserAuthenticationRequired(true)在使用key之前用户的身份需要被认证。

每次KeyGenParameterSpec创建的时候，他都被用来初始化KeyGenerator，这个对象会产生存储在设备上的key。

### 处理用户指纹认证结果

FingerprintManager.AuthenticationCallback 类回调认证的结果

下面我们简要介绍一下这些接口的含义：

1. OnAuthenticationError（int errorCode, ICharSequence errString） 这个接口会在系统指纹认证出现不可恢复的错误的时候才会调用，并且参数errorCode就给出了错误码，标识了错误的原因。这个时候app能做的只能是提示用户重新尝试一遍。

2. OnAuthenticationFailed() 这个接口会在系统指纹认证失败的情况的下才会回调。注意这里的认证失败和上面的认证错误是不一样的，虽然结果都是不能认证。认证失败是指所有的信息都采集完整，并且没有任何异常，但是这个指纹和之前注册的指纹是不相符的；但是认证错误是指在采集或者认证的过程中出现了错误，比如指纹传感器工作异常等。也就是说认证失败是一个可以预期的正常情况，而认证错误是不可预期的异常情况。

3. OnAuthenticationHelp(int helpMsgId, ICharSequence helpString) 上面的认证失败是认证过程中的一个异常情况，我们说那种情况是因为出现了不可恢复的错误，而我们这里的OnAuthenticationHelp方法是出现了可以恢复的异常才会调用的。什么是可以恢复的异常呢？一个常见的例子就是：手指移动太快，当我们把手指放到传感器上的时候，如果我们很快地将手指移走的话，那么指纹传感器可能只采集了部分的信息，因此认证会失败。但是这个错误是可以恢复的，因此只要提示用户再次按下指纹，并且不要太快移走就可以解决。

4. OnAuthenticationSucceeded(FingerprintManagerCompati.AuthenticationResult result)这个接口会在认证成功之后回调。我们可以在这个方法中提示用户认证成功。这里需要说明一下，如果我们上面在调用authenticate的时候，我们的CryptoObject不是null的话，那么我们在这个方法中可以通过AuthenticationResult来获得Cypher对象然后调用它的doFinal方法。doFinal方法会检查结果是不是会拦截或者篡改过，如果是的话会抛出一个异常。当我们发现这些异常的时候都应该将认证当做是失败来来处理，为了安全建议大家都这么做。

关于上面的接口还有2点需要补充一下：

1. 上面我们说道OnAuthenticationError 和 OnAuthenticationHelp方法中会有错误或者帮助码以提示为什么认证不成功。Android系统定义了几个错误和帮助码在FingerprintManager类中。

2. 当指纹扫描器正在工作的时候，如果我们取消本次操作的话，系统也会回调OnAuthenticationError方法的，只是这个时候的错误码是FingerprintManager.FINGERPRINT_ERROR_CANCELED（值为5），因此app需要区别对待。

3. 当指纹识别失败后，会调用onAuthenticationFailed()方法，这时候指纹传感器并没有关闭，系统给我们提供了5次重试机会，也就是说，连续调用了5次onAuthenticationFailed()方法后，会调用onAuthenticationError()方法。

4. 当系统调用了onAuthenticationError()和onAuthenticationSucceeded()后，传感器会关闭，只有我们重新授权，再次调用authenticate()方法后才能继续使用指纹识别功能。

5. 当系统回调了onAuthenticationError()方法关闭传感器后，这种情况下再次调用authenticate()会有一段时间的禁用期，也就是说这段时间里是无法再次使用指纹识别的。当然，具体的禁用时间由手机厂商的系统不同而有略微差别，有的是1分钟，有的是30秒等等。而且，由于手机厂商的系统区别，有些系统上调用了onAuthenticationError()后，在禁用时间内，其他APP里面的指纹识别功能也无法使用，甚至系统的指纹解锁功能也无法使用。而有的系统上，在禁用时间内调用其他APP的指纹解锁功能，或者系统的指纹解锁功能，就能立即重置指纹识别功能。

参考：
http://blog.csdn.net/smart_yc/article/details/54895081

#### 第二种方式：创建CryptoObject类对象，使用非对称加密实现指纹识别
非对称加密是用于服务器端连接验证使用，比对称加密具有更高的安全性。


步骤跟使用对称加密方式差不多，主要区别是生成CryptoObject 对象的方式和认证的流程。

非对称加密使用的是签名作为CryptoObject 的构造参数：
CryptoObject cryptObject = new FingerprintManager.CryptoObject(signature);

#### 先生成非对称Key对，私钥用于签名加密，公钥传输给服务器端解密。

```java
/**
* 获取非对称加密密钥
*/
@TargetApi(Build.VERSION_CODES.M)
private fun createKeyPair() {
    // 非对称加密，创建 KeyPairGenerator 对象
    try {
        mKeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC
                , "AndroidKeyStore")
        mKeyPairGenerator?.initialize(
                KeyGenParameterSpec.Builder(KEY_NAME,
                        KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        // Require the user to authenticate with a fingerprint to authorize
                        // every use of the private key
                        .setUserAuthenticationRequired(true)
                        .build())
        mKeyPairGenerator?.generateKeyPair()
    } catch (...）{...}
}
```

#### 生成签名Signature对象：

```java
private val mKeyStore: KeyStore
private var mKeyPairGenerator:KeyPairGenerator? = null
private var mSignature:Signature? = null

init {
    mKeyStore = KeyStore.getInstance(KEYSTORE_NAME)
    mKeyStore.load(null)
}

@TargetApi(Build.VERSION_CODES.M)
private fun initSignature(): Boolean {
    try {
        mSignature = Signature.getInstance("SHA256withECDSA")
        mKeyStore?.load(null)
        val key = mKeyStore?.getKey(KEY_NAME, null) as PrivateKey
        mSignature?.initSign(key)
        return true
    } catch (...){...}
}

companion object {
    private const val KEY_NAME = "com.aaron.fingerscandemo.fingerprint_authentication_asymkey"
    private const val KEYSTORE_NAME = "AndroidKeyStore"                                      
}
```
使用签名对象创建CryptoObject ：
```java
fun buildCryptoObject(): FingerprintManagerCompat.CryptoObject {
    createKeyPair()
    initSignature()
    // 使用签名创建CryptoObject
    return FingerprintManagerCompat.CryptoObject(mSignature)
}
```
#### 身份验证调用authenticate，跟之前那种方式使用一样，在回调中处理认证的结果。
fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);

#### 身份认证成功之后把加密的数据发送给服务器进行数据校验。
```java
Signature signature = mCryptoObject.getSignature();

// Transaction 是发送到后台的数据类，最后一个参数是为了避免重复。
Transaction transaction = new Transaction("user", 1, new SecureRandom().nextLong());
...
    signature.update(transaction.toByteArray()); 
    byte[] sigBytes = signature.sign(); // 生产签名后的数据
    if (mStoreBackend.verify(transaction, sigBytes)) { // 后端使用公钥验证已签名的数据
        ...
    } else {
        ...
    }
...
```
#### 后端使用公钥验证已签名的数据
```java
public boolean verify(Transaction transaction, byte[] transactionSignature) {
    ...
        PublicKey publicKey = mPublicKeys.get(transaction.getUserId());
        Signature verificationFunction = Signature.getInstance("SHA256withECDSA");
        verificationFunction.initVerify(publicKey);
        verificationFunction.update(transaction.toByteArray());
        if (verificationFunction.verify(transactionSignature)) {
            return true;
        }
   ...
    return false;
}
```
参考：
https://www.jianshu.com/p/f6b06f9837e1


官网有这两种方式的源码例子，这里做了简化，带上注释更容易理解

本文源码（带注释）：
https://github.com/StarsAaron/FingerScanDemo/tree/master

Google例子源码：
对称加密方式：android-FingerprintDialog
https://github.com/googlesamples/android-FingerprintDialog

非对称加密方式：android-AsymmetricFingerprintDialog
https://github.com/googlesamples/android-AsymmetricFingerprintDialog
