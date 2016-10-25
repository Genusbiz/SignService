// --------------------------------------------------------------------------------------------------------------------
// <copyright file="TokenSigner.cs" company="Genus AS">
//   (C)2016
// </copyright>
// <summary>
// Implementation of the IExternalSignature interface
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SignService.Models
{
    using System;
    using System.Security.Cryptography;
    using iText.Signatures;

    /// <summary>
    /// The token signer.
    /// </summary>
    internal class TokenSigner : IExternalSignature
    {
        /// <summary>The hash algorithm.</summary>
        private readonly string m_hashAlgorithm;

        /// <summary>The encryption algorithm (obtained from the private key)</summary>
        private readonly string m_encryptionAlgorithm;

        /// <summary>
        /// The private key.
        /// </summary>
        private readonly AsymmetricAlgorithm m_pk;

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenSigner"/> class. 
        /// instance.
        /// </summary>
        /// <param name="pk">
        /// A
        /// <see cref="Org.BouncyCastle.Crypto.ICipherParameters"/>
        /// object.
        /// </param>
        /// <param name="hashAlgorithm">
        /// A hash algorithm (e.g. "SHA-1", "SHA-256",...).
        /// </param>
        public TokenSigner(AsymmetricAlgorithm pk, string hashAlgorithm)
        {
            this.m_pk = pk;
            this.m_hashAlgorithm = DigestAlgorithms.GetDigest(DigestAlgorithms.GetAllowedDigest(hashAlgorithm));
            this.m_encryptionAlgorithm = "RSA";
        }

        /// <summary>
        /// Returns the encryption algorithm.
        /// </summary>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public string GetEncryptionAlgorithm()
        {
            return this.m_encryptionAlgorithm;
        }

        /// <summary>
        /// Returns the hash algorithm.
        /// </summary>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public string GetHashAlgorithm()
        {
            return this.m_hashAlgorithm;
        }

        /// <summary>
        /// Signs the provided byte array and returns the signed data.
        /// </summary>
        /// <param name="message">
        /// The message.
        /// </param>
        /// <returns>
        /// The <see cref="byte[]"/>.
        /// </returns>
        /// <exception cref="Exception">
        /// Throws when the signature algorithm is not a RASCryptoServiceProvider
        /// </exception>
        public byte[] Sign(byte[] message)
        {
            byte[] l_signedData;
            var l_cryptoServiceProvider = this.m_pk as RSACryptoServiceProvider;
            if (l_cryptoServiceProvider != null)
            {
                l_signedData = l_cryptoServiceProvider.SignData(message, new SHA256CryptoServiceProvider());
            }
            else
            {
                throw new Exception("Invalid algorithm: " + this.m_pk.SignatureAlgorithm);
            }

            return l_signedData;
        }
    }
}
