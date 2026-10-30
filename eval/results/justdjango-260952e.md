# Evaluation: https://github.com/justdjango/django-ecommerce @ `260952e75344`

Oracle: the project run under `justdjango.py` (38 steps) on Python 3.8.20 with django 2.2.14, pillow 6.2.2, requests 2.21.0. 1145 modules loaded, 2434 functions ran.

**Verdict: sound** — no clear was contradicted and every loaded module was in the closure.

| Measure | Result |
| --- | --- |
| Alerts | 137 |
| Decided with evidence | 31 (22.6%): 16 cleared, 15 reachable |
| Clears contradicted by the run (module loaded) | 0 of 16 |
| Modules loaded at run time but missing from the closure | 0 of 776 (plus 89 with no Python source file to scan) |
| Reachable alerts whose vulnerable function ran | 12 of 15 (3 not exercised by the workload) |
| Open alerts whose picked function ran | 8 |
| Function picks matching gold labels | 8 of 9 |
| Model cost of a scan without recordings | $3.6147 total, $0.02638 per alert |
| Scan time | 16 s |

## Reachable alerts

| Advisory | Vulnerable function | Ran under the workload |
| --- | --- | --- |
| GHSA-2gwj-7jmv-h26r | `django.db.models.sql.query.Query.add_annotation` | yes |
| GHSA-6cw3-g6wv-c2xv | `django.http.multipartparser.MultiPartParser.parse` | yes |
| GHSA-frmv-pr5f-9mcr | `django.db.models.query_utils.Q.__init__` | yes |
| GHSA-fvgf-6h6h-3322 | `django.utils.archive.TarArchive.extract` | not exercised |
| GHSA-qw25-v68c-qjf3 | `django.http.response.HttpResponseRedirectBase.__init__` | yes |
| GHSA-4fx9-vc88-q2xc | `PIL.JpegImagePlugin.JpegImageFile.load_read` | not exercised |
| GHSA-74r2-7ff9-mjj2 | `PIL.GifImagePlugin.GifImageFile._seek` | yes |
| GHSA-95q3-8gr9-gm8w | `PIL.IcoImagePlugin.IcoFile.frame` | yes |
| GHSA-98vv-pw6r-q6q4 | `PIL.ImageColor.getrgb` | not exercised |
| GHSA-f5g8-5qq7-938w | `PIL.PcxImagePlugin.PcxImageFile._open` | yes |
| GHSA-g6rj-rv7j-xwp4 | `PIL.PsdImagePlugin._layerinfo` | yes |
| GHSA-m2vv-5vj5-2hm7 | `PIL.GifImagePlugin.GifImageFile._seek` | yes |
| GHSA-p8hx-v2p6-rp84 | `PIL.DcxImagePlugin.DcxImageFile.seek` | yes |
| GHSA-q5hq-fp76-qmrc | `PIL.EpsImagePlugin.PSFile.readline` | yes |
| GHSA-xgh8-jp6q-p5x8 | `PIL.XbmImagePlugin.XbmImageFile._open` | yes |

## Cleared alerts

| Advisory | Module(s) the clear rests on | Loaded at run time |
| --- | --- | --- |
| GHSA-68w8-qjq3-2gfm | `django.contrib.admindocs.views` | no |
| GHSA-crhf-3pfg-w68w | `django.contrib.gis.gdal.raster.source` | no |
| GHSA-fr28-569j-53c4 | `django.core.cache.backends.filebased` | no |
| GHSA-q238-5cxm-5c9h | `django.contrib.gis.db.models.fields`, `django.contrib.gis.forms.fields`, `django.contrib.gis.geos.geometry`, `django.contrib.gis.geos.prototypes.io` | no |
| GHSA-wvqv-fj8w-qmhm | `django.contrib.gis.db.models.fields`, `django.contrib.gis.gdal.raster.source` | no |
| GHSA-hj66-6f7g-4r5v | `oauthlib.oauth2.rfc6749.endpoints.revocation` | no |
| GHSA-xpv3-w29h-x7cv | `oauthlib.oauth2.rfc6749.grant_types.authorization_code` | no |
| GHSA-3f63-hfp8-52jq | `PIL.ImageMath` | no |
| GHSA-3j72-p6qg-6xp7 | `PIL.TarIO` | no |
| GHSA-45hq-cxwh-f6vc | `PIL.BdfFontFile` | no |
| GHSA-5x94-69rx-g8h2 | `PIL.FontFile` | no |
| GHSA-8ghj-p4vj-mr35 | `PIL.ImageFont` | no |
| GHSA-8v84-f9pq-wr9x | `PIL.PcfFontFile` | no |
| GHSA-8vj2-vxx3-667w | `PIL.ImageMath` | no |
| GHSA-9hw9-ch79-4vh6 | `PIL.ImageCms` | no |
| GHSA-phj9-mv4w-65pm | `PIL.GdImageFile` | no |

## Loaded but not in the closure

- `PIL._imaging` (no Python source file: a compiled extension, a namespace package or an alias)
- `PIL._webp` (no Python source file: a compiled extension, a namespace package or an alias)
- `core.management` (no Python source file: a compiled extension, a namespace package or an alias)
- `core.templatetags` (no Python source file: a compiled extension, a namespace package or an alias)
- `django.contrib.sessions.management` (no Python source file: a compiled extension, a namespace package or an alias)
- `django.contrib.staticfiles.management` (no Python source file: a compiled extension, a namespace package or an alias)
- `django.core.management.commands` (no Python source file: a compiled extension, a namespace package or an alias)
- `django.utils.six.moves` (no Python source file: a compiled extension, a namespace package or an alias)
- `django.utils.six.moves.urllib` (no Python source file: a compiled extension, a namespace package or an alias)
- `django.utils.six.moves.urllib.parse` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.big5freq` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.big5prober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.chardistribution` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.charsetgroupprober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.charsetprober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.codingstatemachine` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.compat` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.cp949prober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.enums` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.escprober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.escsm` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.eucjpprober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.euckrfreq` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.euckrprober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.euctwfreq` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.euctwprober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.gb2312freq` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.gb2312prober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.hebrewprober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.jisfreq` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.jpcntx` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.langbulgarianmodel` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.langcyrillicmodel` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.langgreekmodel` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.langhebrewmodel` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.langthaimodel` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.langturkishmodel` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.latin1prober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.mbcharsetprober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.mbcsgroupprober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.mbcssm` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.sbcharsetprober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.sbcsgroupprober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.sjisprober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.universaldetector` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.utf8prober` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.chardet.version` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.idna` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.idna.core` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.idna.idnadata` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.idna.intranges` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.idna.package_data` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3._collections` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.connection` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.connectionpool` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.contrib` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.contrib._appengine_environ` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.exceptions` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.fields` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.filepost` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.packages` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.packages.six` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.packages.six.moves` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.packages.six.moves.http_client` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.packages.six.moves.urllib` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.packages.six.moves.urllib.parse` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.packages.ssl_match_hostname` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.poolmanager` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.request` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.response` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.util` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.util.connection` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.util.queue` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.util.request` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.util.response` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.util.retry` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.util.ssl_` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.util.timeout` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.util.url` (no Python source file: a compiled extension, a namespace package or an alias)
- `requests.packages.urllib3.util.wait` (no Python source file: a compiled extension, a namespace package or an alias)
- `stripe.six.moves` (no Python source file: a compiled extension, a namespace package or an alias)
- `stripe.six.moves.urllib` (no Python source file: a compiled extension, a namespace package or an alias)
- `stripe.six.moves.urllib.parse` (no Python source file: a compiled extension, a namespace package or an alias)
- `urllib3.packages.six.moves` (no Python source file: a compiled extension, a namespace package or an alias)
- `urllib3.packages.six.moves.http_client` (no Python source file: a compiled extension, a namespace package or an alias)
- `urllib3.packages.six.moves.urllib` (no Python source file: a compiled extension, a namespace package or an alias)
- `urllib3.packages.six.moves.urllib.parse` (no Python source file: a compiled extension, a namespace package or an alias)

## Open alerts whose picked function ran

Leads the path search missed; running a function does not by itself mean the vulnerable input can reach it.

- GHSA-8c5j-9r9f-c6w8: `django.template.defaultfilters._property_resolver, django.template.defaultfilters.dictsort, django.template.defaultfilters.dictsortreversed`
- GHSA-jrh2-hc4r-7jwx: `django.core.files.storage.FileSystemStorage._save, django.core.files.storage.Storage.generate_filename, django.core.files.storage.Storage.get_available_name, django.core.files.storage.Storage.save`
- GHSA-m6gj-h9gm-gw44: `django.core.files.storage.FileSystemStorage._save`
- GHSA-rxjp-mfm9-w4wr: `django.core.files.uploadedfile.UploadedFile._set_name, django.db.models.fields.files.FileField.generate_filename, django.core.files.storage.Storage.generate_filename, django.core.files.storage.Storage.get_available_name, django.utils.text.get_valid_filename`
- GHSA-v6rh-hp5x-86rv: `django.urls.resolvers.RegexPattern.match, django.urls.resolvers._route_to_regex`
- GHSA-2m57-hf25-phgg: `sqlparse.sql.TokenList.flatten`
- GHSA-prg7-hcfm-mfcr: `sqlparse.lexer.Lexer.get_tokens`
- GHSA-pwgv-4x5q-6m9f: `sqlparse.sql.TokenList.__init__`

## Function picks against gold labels

- GHSA-95q3-8gr9-gm8w: correct (picked PIL.IcoImagePlugin.IcoFile.frame)
- GHSA-3wvg-mj6g-m9cv: correct (picked PIL.IcnsImagePlugin.read_png_or_jpeg2000)
- GHSA-f4w8-cv6p-x6r5: WRONG (picked PIL.BlpImagePlugin.BLP1Decoder._decode_jpeg_stream)
- GHSA-5x94-69rx-g8h2: correct (picked PIL.FontFile.FontFile.compile)
- GHSA-45hq-cxwh-f6vc: correct (picked PIL.BdfFontFile.bdf_char)
- GHSA-9hw9-ch79-4vh6: correct (picked PIL.ImageCms.ImageCmsTransform.apply)
- GHSA-3f63-hfp8-52jq: correct (picked PIL.ImageMath.eval)
- GHSA-h7pc-vwp9-298g: correct (picked django.http.request.HttpRequest.get_signed_cookie, django.http.response.HttpResponseBase.set_signed_cookie)
- GHSA-frmv-pr5f-9mcr: correct (picked django.db.models.query_utils.Q.__init__)

## What this does and does not show

- A run can falsify a clear (the module loaded) but cannot prove one: a module that did not load under this workload might load under another. The closure check is the stronger test: every module that loaded must be one the scan said could load.
- A vulnerable function that ran shows the call path is real, not that an exploit works: conditions inside functions are not modelled. One that did not run was not exercised by this workload; it is not evidence against the path.
- The oracle runs the project on the Python version noted above, with the exact package versions the scan analysed.
