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

In accordance with Section 7(b) of the GNU Affero General Public License,
a covered work must retain the producer line in every PDF that is created
or manipulated using iText.

You can be released from the requirements of the license by purchasing
a commercial license. Buying such a license is mandatory as soon as you
develop commercial activities involving the iText software without
disclosing the source code of your own applications.
These activities include: offering paid services to customers as an ASP,
serving PDFs on the fly in a web application, shipping iText with a closed
source product.

For more information, please contact iText Software Corp. at this
address: sales@itextpdf.com
*/

namespace SignService.Models
{
    using System;
    using System.Configuration;
    using System.IO;
    using System.Security;
    using System.Security.AccessControl;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using iText.Kernel.Geom;
    using iText.Kernel.Pdf;
    using iText.Signatures;

    using Org.BouncyCastle.Security;

    using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

    /// <summary>
    /// This class signs a PDF-document.
    /// </summary>
    internal class PdfDocumentSigner
    {
        /// <summary>
        /// Gets the certificate from the current users store.
        /// </summary>
        /// <returns>
        /// The <see cref="X509Certificate2"/>.
        /// </returns>
        private static X509Certificate2 GetCertificate()
        {
            // Open personal certificate store for the logged-in user
            var l_certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            var l_issuerName = ConfigurationManager.AppSettings["CertificateIssuerName"];


            l_certStore.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

            // Get all certificates in store
            var l_certs = l_certStore.Certificates;
            l_certStore.Close();

            // A sequence of filtering operations follows to end up with the certificate we should use.
            // Could use enumeration instead.

            // 1. Filter out expired certificates
            l_certs = l_certs.Find(X509FindType.FindByTimeValid, DateTime.Now, true);

            // 2. Filter on issuer.
            // NOTE! Issuer name may change.
            l_certs = l_certs.Find(X509FindType.FindByIssuerName, l_issuerName, true);

            // 3. Filter on key usage. We usually want NonRepudiation for document signatures
            l_certs = l_certs.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.NonRepudiation, true);

            // If only one user's certificates are in the store,
            // we should be left with only one certificate at this point.
            if (l_certs.Count > 1)
            {
                // If there are still more than one, let the user choose
                throw new Exception(
                    $"There are more than one valid, non-expired, non-repudiation certificates issued by '{l_issuerName}' available in the certificate store");
            }

            // At this point, there is 1 or 0 certificates in the collection
            return l_certs.Count == 0 ? null : l_certs[0];
        }

        /// <summary>
        /// Extracts the private key from the certificate
        /// </summary>
        /// <param name="cert">
        /// The certificate to extract the private key from.
        /// </param>
        /// <param name="pin">
        /// The pin-code used to extract the key.
        /// </param>
        /// <returns>
        /// The <see cref="RSACryptoServiceProvider"/>.
        /// </returns>
        private static RSACryptoServiceProvider GetKey(X509Certificate2 cert, string pin)
        {
            if (!cert.HasPrivateKey)
            {
                throw new InvalidOperationException($"This certificate does not contain a private key. The certificate name is '{cert.FriendlyName}'");
            }

            if (pin != null)
            {
                // Supplying a PIN to the card programmatically:
                var l_spin = new SecureString();
                foreach (var l_c in pin)
                {
                    l_spin.AppendChar(l_c);
                }

                // RSACryptoServiceProvider tmprsaprov = (RSACryptoServiceProvider)cert.PrivateKey;
                var l_cspkci = ((RSACryptoServiceProvider) cert.PrivateKey).CspKeyContainerInfo;
                var l_cspp = new CspParameters(
                    1,
                    l_cspkci.ProviderName,
                    l_cspkci.KeyContainerName,
                    new CryptoKeySecurity(),
                    l_spin);
                l_cspp.Flags |= CspProviderFlags.UseExistingKey;
                l_cspp.KeyNumber = (int) l_cspkci.KeyNumber;
                return new RSACryptoServiceProvider(l_cspp);
            }
            else
            {
                return (RSACryptoServiceProvider) cert.PrivateKey;
            }
        }

        /// <summary>
        /// Signs the PDF-document using the provided parameters.
        /// </summary>
        /// <param name="src">
        /// The source document.
        /// </param>
        /// <param name="destFilename">
        /// The destination filename.
        /// </param>
        internal static void SignDocumentStream(Stream src, string destFilename)
        {
            const string l_fieldname = "Signature1";
            var l_reason = ConfigurationManager.AppSettings["SigningReason"];
            var l_location = ConfigurationManager.AppSettings["SigningLocation"];
            var l_pin = ConfigurationManager.AppSettings["TokenPin"];
            var l_signatureVisible = bool.Parse(ConfigurationManager.AppSettings["SignatureVisible"]);
            var l_x = int.Parse(ConfigurationManager.AppSettings["SignaturePosition_X"]);
            var l_y = int.Parse(ConfigurationManager.AppSettings["SignaturePosition_Y"]);
            var l_w = int.Parse(ConfigurationManager.AppSettings["SignatureWidth"]);
            var l_h = int.Parse(ConfigurationManager.AppSettings["SignatureHeight"]);

            var l_cert = GetCertificate();

            // This is risky business. The private key part of the certificate is protected by a pin-code. 
            // This solution reads the pin-code from web.config and enters it automatically. This circumvention
            // of the built-in security-layer must be mitigated by thorough security in the infrastructure 
            // where the solution runs. 
            var l_key = GetKey(l_cert, l_pin);

            // Find the number of pages in the document
            var l_document = new PdfDocument(new PdfReader(src), new PdfWriter(destFilename + "_temp"));
            var l_pageCount = l_document.GetNumberOfPages();
            l_document.Close();



            // Create certificate chain (might add validation)
            var l_ch = X509Chain.Create();
            l_ch.Build(l_cert);

            // Convert chain to BC classes
            var l_chain = new X509Certificate[l_ch.ChainElements.Count];
            var l_chainElements = new X509ChainElement[l_ch.ChainElements.Count];
            l_ch.ChainElements.CopyTo(l_chainElements, 0);
            for (var l_i = 0; l_i < l_ch.ChainElements.Count; l_i++)
            {
                l_chain[l_i] = DotNetUtilities.FromX509Certificate(l_chainElements[l_i].Certificate);
            }

            var l_reader = new PdfReader(destFilename + "_temp");
            var l_signer = new PdfSigner(l_reader, new FileStream(destFilename, FileMode.OpenOrCreate), false);

            // Creating the appearance
            var l_appearance =
                    l_signer.GetSignatureAppearance()
                        .SetReason(l_reason)
                        .SetLocation(l_location)
                        .SetReuseAppearance(false);

            if (l_signatureVisible)
            {
                // Define rectangle for visible signature
                var l_rect = new Rectangle(l_x, l_y, l_w, l_h);
                l_appearance.SetPageRect(l_rect).SetPageNumber(l_pageCount);
            }

            l_signer.SetFieldName(l_fieldname);

            // Creating the signature, providing our own implementation of IExternalSignature
            IExternalSignature l_pks = new TokenSigner(l_key, DigestAlgorithms.SHA256);
            l_signer.SignDetached(l_pks, l_chain, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
        }
    }
}