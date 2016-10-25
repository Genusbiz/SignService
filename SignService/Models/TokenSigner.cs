/*
This file is part of the Genus PdfSignerService (R) project.
Copyright (c) 2016 Genus AS, Norway
Author(s): Sverre Hårstadstrand

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License version 3
as published by the Free Software Foundation with the addition of the
following permission added to Section 15 as permitted in Section 7(a):
FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
ITEXT GROUP. ITEXT GROUP DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
OF THIRD PARTY RIGHTS

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU Affero General Public License for more details.
You should have received a copy of the GNU Affero General Public License
along with this program; if not, see http://www.gnu.org/licenses or write to
the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
Boston, MA, 02110-1301 USA, or download the license from the following URL:
http://itextpdf.com/terms-of-use/

The interactive user interfaces in modified source and object code versions
of this program must display Appropriate Legal Notices, as required under
Section 5 of the GNU Affero General Public License.
*/
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
