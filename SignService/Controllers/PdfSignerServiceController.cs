// --------------------------------------------------------------------------------------------------------------------
// <copyright file="PdfSignerServiceController.cs" company="Genus AS">
//   (C)2016
// </copyright>
// <summary>
//   Defines the PdfSignerServiceController type.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SignService.Controllers
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Web.Http;

    using SignService.Models;

    /// <summary>
    /// Receives a PDF-document to sign in the body of the POST-request. Signs 
    /// the document and returns it in the body of the response.
    /// </summary>
    public class PdfSignerServiceController : ApiController
    {
        /// <summary>
        /// The POST method handler.
        /// </summary>
        /// <returns>
        /// The <see cref="HttpResponseMessage"/>.
        /// </returns>
        public HttpResponseMessage Post()
        {
            var l_task = this.Request.Content.ReadAsStreamAsync();
            l_task.Wait();
            var l_requestStream = l_task.Result;

            var l_filename = System.IO.Path.GetTempFileName();

            PdfDocumentSigner.SignDocumentStream(l_requestStream, l_filename);

            var l_response = new HttpResponseMessage(HttpStatusCode.OK);
            try
            {
                l_response.Content = this.TemporaryFile(l_filename);
                l_response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
                l_response.Content.Headers.ContentDisposition = new ContentDispositionHeaderValue("attachment")
                {
                    FileName = "SignedDocument.pdf"
                };
            }
            catch (Exception l_ex)
            {
                // log your exception details here
                l_response =
                    new HttpResponseMessage(HttpStatusCode.InternalServerError)
                    {
                        Content = new StringContent(l_ex.Message)
                    };
            }

            return l_response;

        }

        /// <summary>
        /// Reads the contents of the temporary signed file into a HttpContent instance, and deletes the file.
        /// </summary>
        /// <param name="fileName">
        /// The file name.
        /// </param>
        /// <returns>
        /// The <see cref="HttpContent"/>.
        /// </returns>
        private HttpContent TemporaryFile(string fileName)
        {
            var l_bytes = File.ReadAllBytes(fileName);
            File.Delete(fileName);
            return new StreamContent(new MemoryStream(l_bytes));
        }
    }
}
