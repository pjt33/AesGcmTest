using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace AesGcmTest
{
    /// <summary>Native wrappers for CNG APIs</summary>
    internal static class BCrypt
    {
        [SecurityCritical]
        internal static SafeBCryptAlgorithmHandle OpenAlgorithm(string algorithm, string implementation)
        {
            ErrorCode error = UnsafeNativeMethods.BCryptOpenAlgorithmProvider(out var algorithmHandle, algorithm, implementation, 0);
            if (error != ErrorCode.Success) throw new CryptographicException("Open algorithm failed with error " + error);
            return algorithmHandle;
        }

        [SecurityCritical]
        internal static byte[] GetProperty(SafeBCryptAlgorithmHandle bcryptObject, string property)
        {
            // Query the space requirements.
            int propertySize = 0;
            ErrorCode error = UnsafeNativeMethods.BCryptGetAlgorithmProperty(bcryptObject, property, null, 0, ref propertySize, 0);
            if (error != ErrorCode.Success && error != ErrorCode.BufferTooSmall) throw new CryptographicException("Failed to get property: error " + error);

            // Get the value.
            byte[] propertyValue = new byte[propertySize];
            error = UnsafeNativeMethods.BCryptGetAlgorithmProperty(bcryptObject, property, propertyValue, propertyValue.Length, ref propertySize, 0);
            if (error != ErrorCode.Success) throw new CryptographicException("Failed to get property: error " + error);

            return propertyValue;
        }

        [SecurityCritical]
        internal static void SetProperty(SafeBCryptAlgorithmHandle bcryptObject, string property, byte[] value)
        {
            ErrorCode error = UnsafeNativeMethods.BCryptSetAlgorithmProperty(bcryptObject, property, value, value.Length, 0);
            if (error != ErrorCode.Success) throw new CryptographicException("Property set failed with error " + error);
        }

        [SecurityCritical]
        internal static SafeBCryptKeyHandle ImportKey(SafeBCryptAlgorithmHandle algorithm, byte[] key)
        {
            const int BCRYPT_KEY_DATA_BLOB_MAGIC = 0x4d42444b;

            // Concatenate the BCRYPT_KEY_DATA_BLOB header and the raw key.
            byte[] keyBlob = new byte[Marshal.SizeOf(typeof(BCRYPT_KEY_DATA_BLOB)) + key.Length];
            unsafe
            {
                fixed (byte* pbKeyBlob = keyBlob)
                {
                    BCRYPT_KEY_DATA_BLOB* pkeyDataBlob = (BCRYPT_KEY_DATA_BLOB*)pbKeyBlob;
                    pkeyDataBlob->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
                    pkeyDataBlob->dwVersion = 1;
                    pkeyDataBlob->cbKeyData = key.Length;
                }
            }
            Buffer.BlockCopy(key, 0, keyBlob, Marshal.SizeOf(typeof(BCRYPT_KEY_DATA_BLOB)), key.Length);

            int cbKeyData = BitConverter.ToInt32(GetProperty(algorithm, "ObjectLength"), 0);
            var pbKeyData = Marshal.AllocCoTaskMem(cbKeyData);

            ErrorCode error = UnsafeNativeMethods.BCryptImportKey(algorithm, IntPtr.Zero, "KeyDataBlob", out var keyHandle, pbKeyData, cbKeyData, keyBlob, keyBlob.Length, 0);
            if (error == ErrorCode.Success)
            {
                keyHandle.DataBuffer = pbKeyData;
                return keyHandle;
            }
            else
            {
                Marshal.FreeCoTaskMem(pbKeyData);
                throw new CryptographicException("Failed to import key: error " + error);
            }
        }
    }

    [SuppressUnmanagedCodeSecurity]
    internal static class UnsafeNativeMethods
    {
        [DllImport("bcrypt.dll")]
        internal static extern ErrorCode BCryptOpenAlgorithmProvider([Out] out SafeBCryptAlgorithmHandle phAlgorithm,
                                                                     [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId,
                                                                     [MarshalAs(UnmanagedType.LPWStr)] string pszImplementation,
                                                                     int dwFlags);

        [DllImport("bcrypt.dll", EntryPoint = "BCryptGetProperty")]
        internal static extern ErrorCode BCryptGetAlgorithmProperty(SafeBCryptAlgorithmHandle hObject,
                                                                    [MarshalAs(UnmanagedType.LPWStr)] string pszProperty,
                                                                    [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbOutput,
                                                                    int cbOutput,
                                                                    [In, Out] ref int pcbResult,
                                                                    int flags);

        [DllImport("bcrypt.dll", EntryPoint = "BCryptSetProperty")]
        internal static extern ErrorCode BCryptSetAlgorithmProperty(SafeBCryptAlgorithmHandle hObject,
                                                                    [MarshalAs(UnmanagedType.LPWStr)] string pszProperty,
                                                                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
                                                                    int cbInput,
                                                                    int dwFlags);

        [DllImport("bcrypt.dll")]
        internal static extern ErrorCode BCryptImportKey(SafeBCryptAlgorithmHandle hAlgorithm,
                                                         IntPtr hImportKey,
                                                         [MarshalAs(UnmanagedType.LPWStr)] string pszBlobType,
                                                         [Out] out SafeBCryptKeyHandle phKey,
                                                         [In, Out] IntPtr pbKeyObject,
                                                         int cbKeyObject,
                                                         [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
                                                         int cbInput,
                                                         int dwFlags);

        [DllImport("bcrypt.dll")]
        internal static extern ErrorCode BCryptDecrypt(SafeBCryptKeyHandle hKey,
                                                       [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
                                                       int cbInput,
                                                       [In, Out] ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
                                                       [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbIV,
                                                       int cbIV,
                                                       [Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbOutput,
                                                       int cbOutput,
                                                       [Out] out int pcbResult,
                                                       int dwFlags);
    }

    internal enum ErrorCode
    {
        Success = 0x00000000,                         // STATUS_SUCCESS
        AuthTagMismatch = unchecked((int)0xC000A002), // STATUS_AUTH_TAG_MISMATCH
        BufferTooSmall = unchecked((int)0xC0000023),  // STATUS_BUFFER_TOO_SMALL
    }

    [Flags]
    internal enum AuthenticatedCipherModeInfoFlags
    {
        None = 0x00000000,
        ChainCalls = 0x00000001 // BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO : IDisposable
    {
        private const int BCRYPT_INIT_AUTH_MODE_INFO_VERSION = 1;

        internal int cbSize;
        internal int dwInfoVersion;

        internal IntPtr pbNonce;
        internal int cbNonce;

        internal IntPtr pbAuthData;
        internal int cbAuthData;

        internal IntPtr pbTag;
        internal int cbTag;

        internal IntPtr pbMacContext;
        internal int cbMacContext;

        internal int cbAAD;
        internal long cbData;
        internal AuthenticatedCipherModeInfoFlags dwFlags;

        [SecurityCritical]
        [SecuritySafeCritical]
        internal void InitGcm(byte[] nonce, byte[] authData, byte[] tag)
        {
            cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
            dwInfoVersion = BCRYPT_INIT_AUTH_MODE_INFO_VERSION;

            _Marshal(nonce, out pbNonce, out cbNonce);
            _Marshal(authData, out pbAuthData, out cbAuthData);
            _Marshal(tag, out pbTag, out cbTag);
            // Needs to be large enough for the largest permitted tag, which is 128 bits
            _Marshal(new byte[16], out pbMacContext, out cbMacContext);

            cbAAD = 0;
            cbData = 0;
            dwFlags = AuthenticatedCipherModeInfoFlags.None;
        }

        [SecurityCritical]
        private static void _Marshal(byte[] buf, out IntPtr ptr, out int len)
        {
            if (buf != null)
            {
                len = buf.Length;
                ptr = Marshal.AllocCoTaskMem(len);
                Marshal.Copy(buf, 0, ptr, len);
            }
            else
            {
                len = 0;
                ptr = IntPtr.Zero;
            }
        }

        [SecurityCritical]
        public void Dispose()
        {
            _Free(ref pbNonce);
            _Free(ref pbAuthData);
            _Free(ref pbTag);
            _Free(ref pbMacContext);
        }

        [SecurityCritical]
        private static void _Free(ref IntPtr ptr)
        {
            if (ptr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(ptr);
                ptr = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct BCRYPT_KEY_DATA_BLOB
    {
        internal int dwMagic;
        internal int dwVersion;
        internal int cbKeyData;
    }

    /// <summary>SafeHandle for a native BCRYPT_ALG_HANDLE</summary>
    internal sealed class SafeBCryptAlgorithmHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeBCryptAlgorithmHandle() : base(true) { }

        [DllImport("bcrypt.dll")]
        [SuppressUnmanagedCodeSecurity]
        private static extern ErrorCode BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int flags);

        protected override bool ReleaseHandle() => BCryptCloseAlgorithmProvider(handle, 0) == ErrorCode.Success;
    }

    /// <summary>SafeHandle for a native BCRYPT_KEY_HANDLE</summary>
    internal sealed class SafeBCryptKeyHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeBCryptKeyHandle() : base(true) { }

        public override bool IsInvalid => handle == IntPtr.Zero && DataBuffer == IntPtr.Zero;

        internal IntPtr DataBuffer { get; set; }

        [DllImport("bcrypt.dll")]
        [SuppressUnmanagedCodeSecurity]
        private static extern ErrorCode BCryptDestroyKey(IntPtr hKey);

        protected sealed override bool ReleaseHandle()
        {
            if (DataBuffer != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(DataBuffer);
                DataBuffer = IntPtr.Zero;
            }

            return handle != IntPtr.Zero && BCryptDestroyKey(handle) == ErrorCode.Success;
        }
    }
}
