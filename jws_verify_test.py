# -*- coding: UTF-8 -*-
"""
@Description: 描述
@Project ：apple-subsciption-tools 
@File    ：jws_verify_test.py
@IDE     ：PyCharm 
@Author  ：noobcoderr
@Date    ：2023/4/13 22:00 
"""
import unittest

from jws_verify import AppleIapTools

test_jws = "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTURDQ0E3YWdBd0lCQWdJUWFQb1BsZHZwU29FSDBsQnJqRFB2OWpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJeE1EZ3lOVEF5TlRBek5Gb1hEVEl6TURreU5EQXlOVEF6TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCT29UY2FQY3BlaXBOTDllUTA2dEN1N3BVY3dkQ1hkTjh2R3FhVWpkNThaOHRMeGlVQzBkQmVBK2V1TVlnZ2gxLzVpQWsrRk14VUZtQTJhMXI0YUNaOFNqZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRkNPQ21NQnEvLzFMNWltdlZtcVgxb0NZZXFyTU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3Tm9BREJsQWpFQWw0SkI5R0pIaXhQMm51aWJ5VTFrM3dyaTVwc0dJeFBNRTA1c0ZLcTdoUXV6dmJleUJ1ODJGb3p6eG1ienBvZ29BakJMU0ZsMGRaV0lZbDJlalBWK0RpNWZCbktQdThteW1CUXRvRS9IMmJFUzBxQXM4Yk51ZVUzQ0JqamgxbHduRHNJPSIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJub3RpZmljYXRpb25UeXBlIjoiRElEX0NIQU5HRV9SRU5FV0FMX1NUQVRVUyIsInN1YnR5cGUiOiJBVVRPX1JFTkVXX0RJU0FCTEVEIiwibm90aWZpY2F0aW9uVVVJRCI6ImY4OTM4OTBkLTk5ZjktNGYxNy1iZmUxLTEzOTcwMzE5ZjI2MCIsImRhdGEiOnsiYXBwQXBwbGVJZCI6MTUxNTY1NzE4NSwiYnVuZGxlSWQiOiJjb20udHV5b28udGVzdGluZyIsImJ1bmRsZVZlcnNpb24iOiIxMTIyIiwiZW52aXJvbm1lbnQiOiJTYW5kYm94Iiwic2lnbmVkVHJhbnNhY3Rpb25JbmZvIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxGVFVSRFEwRTNZV2RCZDBsQ1FXZEpVV0ZRYjFCc1pIWndVMjlGU0RCc1FuSnFSRkIyT1dwQlMwSm5aM0ZvYTJwUFVGRlJSRUY2UWpGTlZWRjNVV2RaUkZaUlVVUkVSSFJDWTBoQ2MxcFRRbGhpTTBweldraGtjRnBIVldkU1IxWXlXbGQ0ZG1OSFZubEpSa3BzWWtkR01HRlhPWFZqZVVKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVXhOUVd0SFFURlZSVU4zZDBOU2VsbDRSWHBCVWtKblRsWkNRVzlOUTJ0R2QyTkhlR3hKUld4MVdYazBlRU42UVVwQ1owNVdRa0ZaVkVGc1ZsUk5RalJZUkZSSmVFMUVaM2xPVkVGNVRsUkJlazVHYjFoRVZFbDZUVVJyZVU1RVFYbE9WRUY2VFRGdmQyZGFTWGhSUkVFclFtZE9Wa0pCVFUxT01VSjVZakpSWjFKVlRrUkpSVEZvV1hsQ1FtTklRV2RWTTFKMlkyMVZaMWxYTld0SlIyeFZaRmMxYkdONVFsUmtSemw1V2xOQ1UxcFhUbXhoV0VJd1NVWk9jRm95TlhCaWJXTjRURVJCY1VKblRsWkNRWE5OU1RCR2QyTkhlR3hKUm1SMlkyMTRhMlF5Ykd0YVUwSkZXbGhhYkdKSE9YZGFXRWxuVlcxV2MxbFlVbkJpTWpWNlRWSk5kMFZSV1VSV1VWRkxSRUZ3UW1OSVFuTmFVMEpLWW0xTmRVMVJjM2REVVZsRVZsRlJSMFYzU2xaVmVrSmFUVUpOUjBKNWNVZFRUVFE1UVdkRlIwTkRjVWRUVFRRNVFYZEZTRUV3U1VGQ1QyOVVZMkZRWTNCbGFYQk9URGxsVVRBMmRFTjFOM0JWWTNka1ExaGtUamgyUjNGaFZXcGtOVGhhT0hSTWVHbFZRekJrUW1WQksyVjFUVmxuWjJneEx6VnBRV3NyUmsxNFZVWnRRVEpoTVhJMFlVTmFPRk5xWjJkSlNVMUpTVU5DUkVGTlFtZE9Wa2hTVFVKQlpqaEZRV3BCUVUxQ09FZEJNVlZrU1hkUldVMUNZVUZHUkRoMmJFTk9VakF4UkVwdGFXYzVOMkpDT0RWaksyeHJSMHRhVFVoQlIwTkRjMGRCVVZWR1FuZEZRa0pIVVhkWmFrRjBRbWRuY2tKblJVWkNVV04zUVc5WmFHRklVakJqUkc5MlRESk9iR051VW5wTWJVWjNZMGQ0YkV4dFRuWmlVemt6WkRKU2VWcDZXWFZhUjFaNVRVUkZSME5EYzBkQlVWVkdRbnBCUW1ocFZtOWtTRkozVDJrNGRtSXlUbnBqUXpWb1kwaENjMXBUTldwaU1qQjJZakpPZW1ORVFYcE1XR1F6V2toS2JrNXFRWGxOU1VsQ1NHZFpSRlpTTUdkQ1NVbENSbFJEUTBGU1JYZG5aMFZPUW1kdmNXaHJhVWM1TWs1clFsRlpRazFKU0N0TlNVaEVRbWRuY2tKblJVWkNVV05EUVdwRFFuUm5lVUp6TVVwc1lrZHNhR0p0VG14SlJ6bDFTVWhTYjJGWVRXZFpNbFo1WkVkc2JXRlhUbWhrUjFWbldXNXJaMWxYTlRWSlNFSm9ZMjVTTlVsSFJucGpNMVowV2xoTloxbFhUbXBhV0VJd1dWYzFhbHBUUW5aYWFVSXdZVWRWWjJSSGFHeGlhVUpvWTBoQ2MyRlhUbWhaYlhoc1NVaE9NRmxYTld0WldFcHJTVWhTYkdOdE1YcEpSMFoxV2tOQ2FtSXlOV3RoV0ZKd1lqSTFla2xIT1cxSlNGWjZXbE4zWjFreVZubGtSMnh0WVZkT2FHUkhWV2RqUnpsellWZE9OVWxIUm5WYVEwSnFXbGhLTUdGWFduQlpNa1l3WVZjNWRVbElRbmxaVjA0d1lWZE9iRWxJVGpCWldGSnNZbGRXZFdSSVRYVk5SRmxIUTBOelIwRlJWVVpDZDBsQ1JtbHdiMlJJVW5kUGFUaDJaRE5rTTB4dFJuZGpSM2hzVEcxT2RtSlRPV3BhV0Vvd1lWZGFjRmt5UmpCYVYwWXhaRWRvZG1OdGJEQmxVemgzU0ZGWlJGWlNNRTlDUWxsRlJrTlBRMjFOUW5Fdkx6Rk1OV2x0ZGxadGNWZ3hiME5aWlhGeVRVMUJORWRCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVVVKbmIzRm9hMmxIT1RKT2EwSm5jMEpDUVVsR1FVUkJTMEpuWjNGb2EycFBVRkZSUkVGM1RtOUJSRUpzUVdwRlFXdzBTa0k1UjBwSWFYaFFNbTUxYVdKNVZURnJNM2R5YVRWd2MwZEplRkJOUlRBMWMwWkxjVGRvVVhWNmRtSmxlVUoxT0RKR2IzcDZlRzFpZW5CdloyOUJha0pNVTBac01HUmFWMGxaYkRKbGFsQldLMFJwTldaQ2JrdFFkVGh0ZVcxQ1VYUnZSUzlJTW1KRlV6QnhRWE00WWs1MVpWVXpRMEpxYW1neGJIZHVSSE5KUFNJc0lrMUpTVVJHYWtORFFYQjVaMEYzU1VKQlowbFZTWE5IYUZKM2NEQmpNbTUyVlRSWlUzbGpZV1pRVkdwNllrNWpkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5ha1YzVFhwRk0wMXFRWHBPZWtWM1YyaGpUazE2V1hkTmVrVTFUVVJCZDAxRVFYZFhha0l4VFZWUmQxRm5XVVJXVVZGRVJFUjBRbU5JUW5OYVUwSllZak5LYzFwSVpIQmFSMVZuVWtkV01scFhlSFpqUjFaNVNVWktiR0pIUmpCaFZ6bDFZM2xDUkZwWVNqQmhWMXB3V1RKR01HRlhPWFZKUlVZeFpFZG9kbU50YkRCbFZFVk1UVUZyUjBFeFZVVkRkM2REVW5wWmVFVjZRVkpDWjA1V1FrRnZUVU5yUm5kalIzaHNTVVZzZFZsNU5IaERla0ZLUW1kT1ZrSkJXVlJCYkZaVVRVaFpkMFZCV1VoTGIxcEplbW93UTBGUldVWkxORVZGUVVOSlJGbG5RVVZpYzFGTFF6azBVSEpzVjIxYVdHNVlaM1I0ZW1SV1NrdzRWREJUUjFsdVowUlNSM0J1WjI0elRqWlFWRGhLVFVWaU4wWkVhVFJpUW0xUWFFTnVXak12YzNFMlVFWXZZMGRqUzFoWGMwdzFkazkwWlZKb2VVbzBOWGd6UVZOUU4yTlBRaXRoWVc4NU1HWmpjSGhUZGk5RldrWmlibWxCWWs1bldrZG9TV2h3U1c4MFNEWk5TVWd6VFVKSlIwRXhWV1JGZDBWQ0wzZFJTVTFCV1VKQlpqaERRVkZCZDBoM1dVUldVakJxUWtKbmQwWnZRVlYxTjBSbGIxWm5lbWxLY1d0cGNHNWxkbkl6Y25JNWNreEtTM04zVW1kWlNVdDNXVUpDVVZWSVFWRkZSVTlxUVRSTlJGbEhRME56UjBGUlZVWkNla0ZDYUdsd2IyUklVbmRQYVRoMllqSk9lbU5ETldoalNFSnpXbE0xYW1JeU1IWmlNazU2WTBSQmVreFhSbmRqUjNoc1kyMDVkbVJIVG1oYWVrMTNUbmRaUkZaU01HWkNSRUYzVEdwQmMyOURjV2RMU1ZsdFlVaFNNR05FYjNaTU1rNTVZa00xYUdOSVFuTmFVelZxWWpJd2RsbFlRbmRpUjFaNVlqSTVNRmt5Um01TmVUVnFZMjEzZDBoUldVUldVakJQUWtKWlJVWkVPSFpzUTA1U01ERkVTbTFwWnprM1lrSTROV01yYkd0SFMxcE5RVFJIUVRGVlpFUjNSVUl2ZDFGRlFYZEpRa0pxUVZGQ1oyOXhhR3RwUnpreVRtdENaMGxDUWtGSlJrRkVRVXRDWjJkeGFHdHFUMUJSVVVSQmQwNXZRVVJDYkVGcVFrRllhRk54TlVsNVMyOW5UVU5RZEhjME9UQkNZVUkyTnpkRFlVVkhTbGgxWmxGQ0wwVnhXa2RrTmtOVGFtbERkRTl1ZFUxVVlsaFdXRzE0ZUdONFptdERUVkZFVkZOUWVHRnlXbGgyVG5KcmVGVXpWR3RWVFVrek0zbDZka1pXVmxKVU5IZDRWMHBET1RrMFQzTmtZMW8wSzFKSFRuTlpSSGxTTldkdFpISXdia1JIWnowaUxDSk5TVWxEVVhwRFEwRmpiV2RCZDBsQ1FXZEpTVXhqV0RocFRreEdVelZWZDBObldVbExiMXBKZW1vd1JVRjNUWGRhZWtWaVRVSnJSMEV4VlVWQmQzZFRVVmhDZDJKSFZXZFZiVGwyWkVOQ1JGRlRRWFJKUldONlRWTlpkMHBCV1VSV1VWRk1SRUl4UW1OSVFuTmFVMEpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJWUk5Ra1ZIUVRGVlJVTm5kMHRSV0VKM1lrZFZaMU5YTldwTWFrVk1UVUZyUjBFeFZVVkNhRTFEVmxaTmQwaG9ZMDVOVkZGM1RrUk5kMDFVWjNoUFZFRXlWMmhqVGsxNmEzZE9SRTEzVFZSbmVFOVVRVEpYYWtKdVRWSnpkMGRSV1VSV1VWRkVSRUpLUW1OSVFuTmFVMEpUWWpJNU1FbEZUa0pKUXpCblVucE5lRXBxUVd0Q1owNVdRa0Z6VFVoVlJuZGpSM2hzU1VWT2JHTnVVbkJhYld4cVdWaFNjR0l5TkdkUldGWXdZVWM1ZVdGWVVqVk5VazEzUlZGWlJGWlJVVXRFUVhCQ1kwaENjMXBUUWtwaWJVMTFUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZRakpOUWtGSFFubHhSMU5OTkRsQlowVkhRbE4xUWtKQlFXbEJNa2xCUWtwcWNFeDZNVUZqY1ZSMGEzbEtlV2RTVFdNelVrTldPR05YYWxSdVNHTkdRbUphUkhWWGJVSlRjRE5hU0hSbVZHcHFWSFY0ZUVWMFdDOHhTRGRaZVZsc00wbzJXVkppVkhwQ1VFVldiMEV2Vm1oWlJFdFlNVVI1ZUU1Q01HTlVaR1J4V0d3MVpIWk5WbnAwU3pVeE4wbEVkbGwxVmxSYVdIQnRhMDlzUlV0TllVNURUVVZCZDBoUldVUldVakJQUWtKWlJVWk1kWGN6Y1VaWlRUUnBZWEJKY1ZvemNqWTVOall2WVhsNVUzSk5RVGhIUVRGVlpFVjNSVUl2ZDFGR1RVRk5Ra0ZtT0hkRVoxbEVWbEl3VUVGUlNDOUNRVkZFUVdkRlIwMUJiMGREUTNGSFUwMDBPVUpCVFVSQk1tZEJUVWRWUTAxUlEwUTJZMGhGUm13MFlWaFVVVmt5WlROMk9VZDNUMEZGV2t4MVRpdDVVbWhJUmtRdk0yMWxiM2xvY0cxMlQzZG5VRlZ1VUZkVWVHNVROR0YwSzNGSmVGVkRUVWN4Yldsb1JFc3hRVE5WVkRneVRsRjZOakJwYlU5c1RUSTNhbUprYjFoME1sRm1lVVpOYlN0WmFHbGtSR3RNUmpGMlRGVmhaMDAyUW1kRU5UWkxlVXRCUFQwaVhYMC5leUowY21GdWMyRmpkR2x2Ymtsa0lqb2lNakF3TURBd01ETXhNRE0xTnpNMU55SXNJbTl5YVdkcGJtRnNWSEpoYm5OaFkzUnBiMjVKWkNJNklqSXdNREF3TURBek1UQXpNalU0TWpRaUxDSjNaV0pQY21SbGNreHBibVZKZEdWdFNXUWlPaUl5TURBd01EQXdNREkwT1RBME56ZzJJaXdpWW5WdVpHeGxTV1FpT2lKamIyMHVkSFY1YjI4dWRHVnpkR2x1WnlJc0luQnliMlIxWTNSSlpDSTZJbU52YlM1MGRYbHZieTUwWlhOMGFXNW5MblJsYzNRd01EZ2lMQ0p6ZFdKelkzSnBjSFJwYjI1SGNtOTFjRWxrWlc1MGFXWnBaWElpT2lJeU1UTXdNamswTkNJc0luQjFjbU5vWVhObFJHRjBaU0k2TVRZNE1URXlORFk1TXpBd01Dd2liM0pwWjJsdVlXeFFkWEpqYUdGelpVUmhkR1VpT2pFMk9ERXhNakUyTnpFd01EQXNJbVY0Y0dseVpYTkVZWFJsSWpveE5qZ3hNVEkwT0Rjek1EQXdMQ0p4ZFdGdWRHbDBlU0k2TVN3aWRIbHdaU0k2SWtGMWRHOHRVbVZ1WlhkaFlteGxJRk4xWW5OamNtbHdkR2x2YmlJc0ltRndjRUZqWTI5MWJuUlViMnRsYmlJNklqVXhNVEV5Wm1WaUxUUXhaVEl0TkdSbVlpMWhZV1UwTFdNelkyWXdZamhqTTJaalpTSXNJbWx1UVhCd1QzZHVaWEp6YUdsd1ZIbHdaU0k2SWxCVlVrTklRVk5GUkNJc0luTnBaMjVsWkVSaGRHVWlPakUyT0RFeE1qUTVNVGs0TlRBc0ltVnVkbWx5YjI1dFpXNTBJam9pVTJGdVpHSnZlQ0o5Lk45MHFZWFFkQXR4bWpFazNPWS1mWG1jYkpCOEFXUGV1dFZyR2djVXFWb0NaTU5BMVUza2xlVWs0NkJNOVVFdGhCTk4xRFJQNkwwUHJ0bTNDZ0x4ZmhnIiwic2lnbmVkUmVuZXdhbEluZm8iOiJleUpoYkdjaU9pSkZVekkxTmlJc0luZzFZeUk2V3lKTlNVbEZUVVJEUTBFM1lXZEJkMGxDUVdkSlVXRlFiMUJzWkhad1UyOUZTREJzUW5KcVJGQjJPV3BCUzBKblozRm9hMnBQVUZGUlJFRjZRakZOVlZGM1VXZFpSRlpSVVVSRVJIUkNZMGhDYzFwVFFsaGlNMHB6V2toa2NGcEhWV2RTUjFZeVdsZDRkbU5IVm5sSlJrcHNZa2RHTUdGWE9YVmplVUpFV2xoS01HRlhXbkJaTWtZd1lWYzVkVWxGUmpGa1IyaDJZMjFzTUdWVVJVeE5RV3RIUVRGVlJVTjNkME5TZWxsNFJYcEJVa0puVGxaQ1FXOU5RMnRHZDJOSGVHeEpSV3gxV1hrMGVFTjZRVXBDWjA1V1FrRlpWRUZzVmxSTlFqUllSRlJKZUUxRVozbE9WRUY1VGxSQmVrNUdiMWhFVkVsNlRVUnJlVTVFUVhsT1ZFRjZUVEZ2ZDJkYVNYaFJSRUVyUW1kT1ZrSkJUVTFPTVVKNVlqSlJaMUpWVGtSSlJURm9XWGxDUW1OSVFXZFZNMUoyWTIxVloxbFhOV3RKUjJ4VlpGYzFiR041UWxSa1J6bDVXbE5DVTFwWFRteGhXRUl3U1VaT2NGb3lOWEJpYldONFRFUkJjVUpuVGxaQ1FYTk5TVEJHZDJOSGVHeEpSbVIyWTIxNGEyUXliR3RhVTBKRldsaGFiR0pIT1hkYVdFbG5WVzFXYzFsWVVuQmlNalY2VFZKTmQwVlJXVVJXVVZGTFJFRndRbU5JUW5OYVUwSktZbTFOZFUxUmMzZERVVmxFVmxGUlIwVjNTbFpWZWtKYVRVSk5SMEo1Y1VkVFRUUTVRV2RGUjBORGNVZFRUVFE1UVhkRlNFRXdTVUZDVDI5VVkyRlFZM0JsYVhCT1REbGxVVEEyZEVOMU4zQlZZM2RrUTFoa1RqaDJSM0ZoVldwa05UaGFPSFJNZUdsVlF6QmtRbVZCSzJWMVRWbG5aMmd4THpWcFFXc3JSazE0VlVadFFUSmhNWEkwWVVOYU9GTnFaMmRKU1UxSlNVTkNSRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDT0VkQk1WVmtTWGRSV1UxQ1lVRkdSRGgyYkVOT1VqQXhSRXB0YVdjNU4ySkNPRFZqSzJ4clIwdGFUVWhCUjBORGMwZEJVVlZHUW5kRlFrSkhVWGRaYWtGMFFtZG5ja0puUlVaQ1VXTjNRVzlaYUdGSVVqQmpSRzkyVERKT2JHTnVVbnBNYlVaM1kwZDRiRXh0VG5aaVV6a3paREpTZVZwNldYVmFSMVo1VFVSRlIwTkRjMGRCVVZWR1FucEJRbWhwVm05a1NGSjNUMms0ZG1JeVRucGpRelZvWTBoQ2MxcFROV3BpTWpCMllqSk9lbU5FUVhwTVdHUXpXa2hLYms1cVFYbE5TVWxDU0dkWlJGWlNNR2RDU1VsQ1JsUkRRMEZTUlhkblowVk9RbWR2Y1docmFVYzVNazVyUWxGWlFrMUpTQ3ROU1VoRVFtZG5ja0puUlVaQ1VXTkRRV3BEUW5SbmVVSnpNVXBzWWtkc2FHSnRUbXhKUnpsMVNVaFNiMkZZVFdkWk1sWjVaRWRzYldGWFRtaGtSMVZuV1c1cloxbFhOVFZKU0VKb1kyNVNOVWxIUm5wak0xWjBXbGhOWjFsWFRtcGFXRUl3V1ZjMWFscFRRblphYVVJd1lVZFZaMlJIYUd4aWFVSm9ZMGhDYzJGWFRtaFpiWGhzU1VoT01GbFhOV3RaV0VwclNVaFNiR050TVhwSlIwWjFXa05DYW1JeU5XdGhXRkp3WWpJMWVrbEhPVzFKU0ZaNldsTjNaMWt5Vm5sa1IyeHRZVmRPYUdSSFZXZGpSemx6WVZkT05VbEhSblZhUTBKcVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsSVFubFpWMDR3WVZkT2JFbElUakJaV0ZKc1lsZFdkV1JJVFhWTlJGbEhRME56UjBGUlZVWkNkMGxDUm1sd2IyUklVbmRQYVRoMlpETmtNMHh0Um5kalIzaHNURzFPZG1KVE9XcGFXRW93WVZkYWNGa3lSakJhVjBZeFpFZG9kbU50YkRCbFV6aDNTRkZaUkZaU01FOUNRbGxGUmtOUFEyMU5RbkV2THpGTU5XbHRkbFp0Y1ZneGIwTlpaWEZ5VFUxQk5FZEJNVlZrUkhkRlFpOTNVVVZCZDBsSVowUkJVVUpuYjNGb2EybEhPVEpPYTBKbmMwSkNRVWxHUVVSQlMwSm5aM0ZvYTJwUFVGRlJSRUYzVG05QlJFSnNRV3BGUVd3MFNrSTVSMHBJYVhoUU1tNTFhV0o1VlRGck0zZHlhVFZ3YzBkSmVGQk5SVEExYzBaTGNUZG9VWFY2ZG1KbGVVSjFPREpHYjNwNmVHMWllbkJ2WjI5QmFrSk1VMFpzTUdSYVYwbFpiREpsYWxCV0swUnBOV1pDYmt0UWRUaHRlVzFDVVhSdlJTOUlNbUpGVXpCeFFYTTRZazUxWlZVelEwSnFhbWd4YkhkdVJITkpQU0lzSWsxSlNVUkdha05EUVhCNVowRjNTVUpCWjBsVlNYTkhhRkozY0RCak1tNTJWVFJaVTNsallXWlFWR3A2WWs1amQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkYWVrVmlUVUpyUjBFeFZVVkJkM2RUVVZoQ2QySkhWV2RWYlRsMlpFTkNSRkZUUVhSSlJXTjZUVk5aZDBwQldVUldVVkZNUkVJeFFtTklRbk5hVTBKRVdsaEtNR0ZYV25CWk1rWXdZVmM1ZFVsRlJqRmtSMmgyWTIxc01HVlVSVlJOUWtWSFFURlZSVU5uZDB0UldFSjNZa2RWWjFOWE5XcE1ha1ZNVFVGclIwRXhWVVZDYUUxRFZsWk5kMGhvWTA1TmFrVjNUWHBGTTAxcVFYcE9la1YzVjJoalRrMTZXWGROZWtVMVRVUkJkMDFFUVhkWGFrSXhUVlZSZDFGbldVUldVVkZFUkVSMFFtTklRbk5hVTBKWVlqTktjMXBJWkhCYVIxVm5Va2RXTWxwWGVIWmpSMVo1U1VaS2JHSkhSakJoVnpsMVkzbENSRnBZU2pCaFYxcHdXVEpHTUdGWE9YVkpSVVl4WkVkb2RtTnRiREJsVkVWTVRVRnJSMEV4VlVWRGQzZERVbnBaZUVWNlFWSkNaMDVXUWtGdlRVTnJSbmRqUjNoc1NVVnNkVmw1TkhoRGVrRktRbWRPVmtKQldWUkJiRlpVVFVoWmQwVkJXVWhMYjFwSmVtb3dRMEZSV1VaTE5FVkZRVU5KUkZsblFVVmljMUZMUXprMFVISnNWMjFhV0c1WVozUjRlbVJXU2t3NFZEQlRSMWx1WjBSU1IzQnVaMjR6VGpaUVZEaEtUVVZpTjBaRWFUUmlRbTFRYUVOdVdqTXZjM0UyVUVZdlkwZGpTMWhYYzB3MWRrOTBaVkpvZVVvME5YZ3pRVk5RTjJOUFFpdGhZVzg1TUdaamNIaFRkaTlGV2taaWJtbEJZazVuV2tkb1NXaHdTVzgwU0RaTlNVZ3pUVUpKUjBFeFZXUkZkMFZDTDNkUlNVMUJXVUpCWmpoRFFWRkJkMGgzV1VSV1VqQnFRa0puZDBadlFWVjFOMFJsYjFabmVtbEtjV3RwY0c1bGRuSXpjbkk1Y2t4S1MzTjNVbWRaU1V0M1dVSkNVVlZJUVZGRlJVOXFRVFJOUkZsSFEwTnpSMEZSVlVaQ2VrRkNhR2x3YjJSSVVuZFBhVGgyWWpKT2VtTkROV2hqU0VKeldsTTFhbUl5TUhaaU1rNTZZMFJCZWt4WFJuZGpSM2hzWTIwNWRtUkhUbWhhZWsxM1RuZFpSRlpTTUdaQ1JFRjNUR3BCYzI5RGNXZExTVmx0WVVoU01HTkViM1pNTWs1NVlrTTFhR05JUW5OYVV6VnFZakl3ZGxsWVFuZGlSMVo1WWpJNU1Ga3lSbTVOZVRWcVkyMTNkMGhSV1VSV1VqQlBRa0paUlVaRU9IWnNRMDVTTURGRVNtMXBaemszWWtJNE5XTXJiR3RIUzFwTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlFrSnFRVkZDWjI5eGFHdHBSemt5VG10Q1owbENRa0ZKUmtGRVFVdENaMmR4YUd0cVQxQlJVVVJCZDA1dlFVUkNiRUZxUWtGWWFGTnhOVWw1UzI5blRVTlFkSGMwT1RCQ1lVSTJOemREWVVWSFNsaDFabEZDTDBWeFdrZGtOa05UYW1sRGRFOXVkVTFVWWxoV1dHMTRlR040Wm10RFRWRkVWRk5RZUdGeVdsaDJUbkpyZUZVelZHdFZUVWt6TTNsNmRrWldWbEpVTkhkNFYwcERPVGswVDNOa1kxbzBLMUpIVG5OWlJIbFNOV2R0WkhJd2JrUkhaejBpTENKTlNVbERVWHBEUTBGamJXZEJkMGxDUVdkSlNVeGpXRGhwVGt4R1V6VlZkME5uV1VsTGIxcEplbW93UlVGM1RYZGFla1ZpVFVKclIwRXhWVVZCZDNkVFVWaENkMkpIVldkVmJUbDJaRU5DUkZGVFFYUkpSV042VFZOWmQwcEJXVVJXVVZGTVJFSXhRbU5JUW5OYVUwSkVXbGhLTUdGWFduQlpNa1l3WVZjNWRVbEZSakZrUjJoMlkyMXNNR1ZVUlZSTlFrVkhRVEZWUlVObmQwdFJXRUozWWtkVloxTlhOV3BNYWtWTVRVRnJSMEV4VlVWQ2FFMURWbFpOZDBob1kwNU5WRkYzVGtSTmQwMVVaM2hQVkVFeVYyaGpUazE2YTNkT1JFMTNUVlJuZUU5VVFUSlhha0p1VFZKemQwZFJXVVJXVVZGRVJFSktRbU5JUW5OYVUwSlRZakk1TUVsRlRrSkpRekJuVW5wTmVFcHFRV3RDWjA1V1FrRnpUVWhWUm5kalIzaHNTVVZPYkdOdVVuQmFiV3hxV1ZoU2NHSXlOR2RSV0ZZd1lVYzVlV0ZZVWpWTlVrMTNSVkZaUkZaUlVVdEVRWEJDWTBoQ2MxcFRRa3BpYlUxMVRWRnpkME5SV1VSV1VWRkhSWGRLVmxWNlFqSk5Ra0ZIUW5seFIxTk5ORGxCWjBWSFFsTjFRa0pCUVdsQk1rbEJRa3BxY0V4Nk1VRmpjVlIwYTNsS2VXZFNUV016VWtOV09HTlhhbFJ1U0dOR1FtSmFSSFZYYlVKVGNETmFTSFJtVkdwcVZIVjRlRVYwV0M4eFNEZFplVmxzTTBvMldWSmlWSHBDVUVWV2IwRXZWbWhaUkV0WU1VUjVlRTVDTUdOVVpHUnhXR3cxWkhaTlZucDBTelV4TjBsRWRsbDFWbFJhV0hCdGEwOXNSVXROWVU1RFRVVkJkMGhSV1VSV1VqQlBRa0paUlVaTWRYY3pjVVpaVFRScFlYQkpjVm96Y2pZNU5qWXZZWGw1VTNKTlFUaEhRVEZWWkVWM1JVSXZkMUZHVFVGTlFrRm1PSGRFWjFsRVZsSXdVRUZSU0M5Q1FWRkVRV2RGUjAxQmIwZERRM0ZIVTAwME9VSkJUVVJCTW1kQlRVZFZRMDFSUTBRMlkwaEZSbXcwWVZoVVVWa3laVE4yT1VkM1QwRkZXa3gxVGl0NVVtaElSa1F2TTIxbGIzbG9jRzEyVDNkblVGVnVVRmRVZUc1VE5HRjBLM0ZKZUZWRFRVY3hiV2xvUkVzeFFUTlZWRGd5VGxGNk5qQnBiVTlzVFRJM2FtSmtiMWgwTWxGbWVVWk5iU3RaYUdsa1JHdE1SakYyVEZWaFowMDJRbWRFTlRaTGVVdEJQVDBpWFgwLmV5SnZjbWxuYVc1aGJGUnlZVzV6WVdOMGFXOXVTV1FpT2lJeU1EQXdNREF3TXpFd016STFPREkwSWl3aVlYVjBiMUpsYm1WM1VISnZaSFZqZEVsa0lqb2lZMjl0TG5SMWVXOXZMblJsYzNScGJtY3VkR1Z6ZERBd09DSXNJbkJ5YjJSMVkzUkpaQ0k2SW1OdmJTNTBkWGx2Ynk1MFpYTjBhVzVuTG5SbGMzUXdNRGdpTENKaGRYUnZVbVZ1WlhkVGRHRjBkWE1pT2pBc0ltbHpTVzVDYVd4c2FXNW5VbVYwY25sUVpYSnBiMlFpT21aaGJITmxMQ0p6YVdkdVpXUkVZWFJsSWpveE5qZ3hNVEkwT1RFNU9EQXlMQ0psYm5acGNtOXViV1Z1ZENJNklsTmhibVJpYjNnaUxDSnlaV05sYm5SVGRXSnpZM0pwY0hScGIyNVRkR0Z5ZEVSaGRHVWlPakUyT0RFeE1qTTNPVGN3TURCOS5OMndXN3RfY0dVdElxRmY3U2dMR3kzNUtXaU1SbzZTbzUxQVJLMjk2dld3M3pmVVZaNnpxNFBPMS02cnh2QUtMeWRhMkNONkZOaDZhQmdmb1NBZHFIQSJ9LCJ2ZXJzaW9uIjoiMi4wIiwic2lnbmVkRGF0ZSI6MTY4MTEyNDkxOTg0NH0.WI3MGZDZ2wCU2iXv69t04JnJ42iSyYmvaXAGFVEB7Iut5rK1hgaeAbdOIGBAaSyVMsi2LWdjxu2hKLg4RIEFNQ"


class TestJwsVerify(unittest.TestCase):

    def test_verify_jws(self):
        # 先验证最外层
        jws_data, err = AppleIapTools.verify_jws(test_jws)
        self.assertTrue(jws_data)
        # 再验证内部2个加密的数据
        transaction_info = AppleIapTools.verify_jws(jws_data.get("data").get("signedTransactionInfo"))
        self.assertTrue(transaction_info)

        renewal_info = AppleIapTools.verify_jws(jws_data.get("data").get("signedRenewalInfo"))
        self.assertTrue(renewal_info)


if __name__ == '__main__':
    unittest.main()