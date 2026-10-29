# Evaluation: https://github.com/henrymbuguak/Shopping-Cart-Using-Django-2.0-and-Python-3.6 @ `1aa90f67f455`

Oracle: the project run under `shop.py` (30 steps) on Python 3.8.20 with django 2.0, pillow 4.3.0. 740 modules loaded, 1783 functions ran.

**Verdict: sound** — no clear was contradicted and every loaded module was in the closure.

| Measure | Result |
| --- | --- |
| Alerts | 94 |
| Decided with evidence | 28 (29.8%): 14 cleared, 14 reachable |
| Clears contradicted by the run (module loaded) | 0 of 14 |
| Modules loaded at run time but missing from the closure | 0 of 470 (plus 1 compiled extension(s) with no source) |
| Reachable alerts whose vulnerable function ran | 13 of 14 (1 not exercised by the workload) |
| Open alerts whose picked function ran | 1 |
| Function picks matching gold labels | 13 of 13 |
| Model cost of a scan without recordings | $0.9503 total, $0.01011 per alert |
| Scan time | 507 s |

## Reachable alerts

| Advisory | Vulnerable function | Ran under the workload |
| --- | --- | --- |
| GHSA-5hg3-6c2f-f3wr | `django.middleware.common.CommonMiddleware.get_full_path_with_slash` | yes |
| GHSA-qw25-v68c-qjf3 | `django.http.response.HttpResponseRedirectBase.__init__` | yes |
| GHSA-rf4j-j272-fj86 | `django.contrib.auth.forms.AuthenticationForm.clean` | yes |
| GHSA-wh4h-v3f2-r2pp | `django.utils.numberformat.format` | yes |
| GHSA-5gm3-px64-rw72 | `PIL.FpxImagePlugin.FpxImageFile._open_index` | yes |
| GHSA-95q3-8gr9-gm8w | `PIL.IcoImagePlugin.IcoFile.frame` | yes |
| GHSA-f5g8-5qq7-938w | `PIL.PcxImagePlugin.PcxImageFile._open` | yes |
| GHSA-g6rj-rv7j-xwp4 | `PIL.PsdImagePlugin._layerinfo` | yes |
| GHSA-m2vv-5vj5-2hm7 | `PIL.GifImagePlugin.GifImageFile._seek` | yes |
| GHSA-p8hx-v2p6-rp84 | `PIL.DcxImagePlugin.DcxImageFile.seek` | yes |
| GHSA-q5hq-fp76-qmrc | `PIL.EpsImagePlugin.PSFile.readline` | yes |
| GHSA-xgh8-jp6q-p5x8 | `PIL.XbmImagePlugin.XbmImageFile._open` | yes |
| PYSEC-2021-317 | `PIL.ImageColor.getrgb` | not exercised |
| PYSEC-2022-42980 | `PIL.TiffImagePlugin.TiffImageFile._setup` | yes |

## Cleared alerts

| Advisory | Module(s) the clear rests on | Loaded at run time |
| --- | --- | --- |
| GHSA-68w8-qjq3-2gfm | `django.contrib.admindocs.views` | no |
| GHSA-crhf-3pfg-w68w | `django.contrib.gis.gdal.raster.source` | no |
| GHSA-hmr4-m2h5-33qx | `django.contrib.postgres.aggregates.general` | no |
| GHSA-q238-5cxm-5c9h | `django.contrib.gis.db.models.fields`, `django.contrib.gis.forms.fields`, `django.contrib.gis.geos.geometry`, `django.contrib.gis.geos.prototypes.io` | no |
| GHSA-wvqv-fj8w-qmhm | `django.contrib.gis.db.models.fields`, `django.contrib.gis.gdal.raster.source` | no |
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

- `PIL._imaging` (compiled extension: no source to scan)

## Open alerts whose picked function ran

Leads the path search missed; running a function does not by itself mean the vulnerable input can reach it.

- GHSA-frmv-pr5f-9mcr: `django.db.models.query_utils.Q.__init__`

## Function picks against gold labels

- GHSA-95q3-8gr9-gm8w: correct (picked PIL.IcoImagePlugin.IcoFile.frame)
- GHSA-3wvg-mj6g-m9cv: correct (picked PIL.IcnsImagePlugin.read_png_or_jpeg2000)
- GHSA-f4w8-cv6p-x6r5: correct (picked none)
- GHSA-5x94-69rx-g8h2: correct (picked PIL.FontFile.FontFile.compile)
- GHSA-45hq-cxwh-f6vc: correct (picked PIL.BdfFontFile.bdf_char)
- GHSA-9hw9-ch79-4vh6: correct (picked PIL.ImageCms.ImageCmsTransform.apply)
- GHSA-3f63-hfp8-52jq: correct (picked PIL.ImageMath.eval)
- GHSA-vfq6-hq5r-27r6: correct (picked django.contrib.auth.forms.PasswordResetForm.save, django.contrib.auth.forms.PasswordResetForm.get_users)
- GHSA-hmr4-m2h5-33qx: correct (picked django.contrib.postgres.aggregates.general.StringAgg.__init__)
- GHSA-rf4j-j272-fj86: correct (picked django.contrib.auth.forms.AuthenticationForm.clean)
- GHSA-5hg3-6c2f-f3wr: correct (picked django.middleware.common.CommonMiddleware.get_full_path_with_slash)
- GHSA-h7pc-vwp9-298g: correct (picked django.http.request.HttpRequest.get_signed_cookie, django.http.response.HttpResponseBase.set_signed_cookie)
- GHSA-frmv-pr5f-9mcr: correct (picked django.db.models.query_utils.Q.__init__)

## What this does and does not show

- A run can falsify a clear (the module loaded) but cannot prove one: a module that did not load under this workload might load under another. The closure check is the stronger test: every module that loaded must be one the scan said could load.
- A vulnerable function that ran shows the call path is real, not that an exploit works: conditions inside functions are not modelled. One that did not run was not exercised by this workload; it is not evidence against the path.
- The oracle runs the project on the Python version noted above, with the exact package versions the scan analysed.
