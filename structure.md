# General structure for my reference

## Setup($1^\lambda$) &rarr; $pp_{\text{SIG}}$ 
Parameters -   
$$pp_{\text{SIG}} \leftarrow  (G_1, G_2, G_T, p, e, g_1, g_2)$$


Hash to curve function -  
$$H:\{0,1\}^* \rightarrow G_1$$

## KeyGen($pp_{\text{SIG}}$) &rarr; $(vk,sk)$

$$x \leftarrow \mathbb{Z_p^*}$$
$$vk = g_2^x \ \epsilon \ \mathbb{G_2}$$
$$sk = x $$

## Sign($sk,m \epsilon \{0,1\}^*$) &rarr; $\sigma$

Compute 
$$ M = H(m) \ \epsilon \ \mathbb{G_1}$$

Signature 
$$ \sigma = M^x$$

## Verify($vk, m, \sigma$) &rarr; 1 or 0

1 if 
$$e(\sigma, g_2) = e(H(m), vk)$$

0 otherwise

## CSetup($1^\lambda, pp_{\text{SIG}}$) &rarr; $pp_{\text{LVACS}}$

Sample
$$a \leftarrow \mathbb{Z_p^*}$$
$$b \leftarrow \mathbb{Z_p}$$

Define
$$ v = (v_1, v_2) = (g_1^a, g_1)$$
$$ w = v^b = (w_1, w_2) = (g_1^{ab}, g_1^b)$$

Output
$$pp_{\text{LVACS}} = v, w$$

## Convert($vk_i, m_i, \sigma_i$) &rarr; $\hat{\sigma_i}, \text{aux}_i$

Compute 
$$M_i = H(m_i)$$

Sample
$$r_{\sigma_i}, s_{\sigma_i}, r_{M_i}, s_{M_i} \leftarrow \mathbb{Z_p}$$

$$
C_{\sigma}^i = 
(C_{\sigma,1}^i, C_{\sigma,2}^i) = 
(v_1^{r_{\sigma_i}}w_1^{s_{\sigma_i}}\ ,\ \sigma_i v_2^{r_{\sigma_i}}w_2^{s_{\sigma_i}})
$$

$$
C_{M}^i = 
(C_{M,1}^i, C_{M,2}^i) = 
(v_1^{r_{M_i}}w_1^{s_{M_i}}\ ,\ M_i v_2^{r_{M_i}}w_2^{s_{M_i}})
$$

$$
\pi^i = 
(\pi_{1}^i, \pi_{2}^i) = 
(g_2^{r_{\sigma_i}}vk_i^{-r_{M_i}}\ ,g_2^{s_{\sigma_i}}vk_i^{-s_{M_i}})
$$

Output
$$\hat{\sigma_i} = (\pi^i, C_{\sigma}^i, C_M^i)$$
$$\text{aux}_i = (r_{\sigma_i}, s_{\sigma_i}, r_{M_i}, s_{M_i})$$

## CVerify($\hat{\sigma_i}, vk_i, v, w$) &rarr; 1 or 0

Output 1 if both 
$$e(C_{\sigma,1}^i, g_2)e(C_{M,1}^i, vk_i^{-1}) = e(v_1, \pi_1^i)e(w_1, \pi_2^i)$$
$$e(C_{\sigma,2}^i, g_2)e(C_{M,2}^i, vk_i^{-1}) = e(v_2, \pi_1^i)e(w_2, \pi_2^i)$$

0 otherwise

## Open($m_i, \hat{\sigma_i}, \text{aux}_i$) &rarr; 1 or 0

Compute
$$M_i = H(m_i)$$

Output 1 if
$$C_M^i = (v_1^{r_{M_i}}w_1^{s_{M_i}}\ ,\ M_i v_2^{r_{M_i}}w_2^{s_{M_i}})$$

0 otherwise

## CAgg($\{vk_i\}^n_{i=1}, \{\hat{\sigma_i}\}^n_{i=1}$) &rarr; $\hat{\sigma}$

Compute
$$C_{\sigma}^{\text{agg}} = 
\prod\limits_{i=1}^{n}C_{\sigma}^i =
(\prod\limits_{i=1}^{n}C_{\sigma,1}^i, \prod\limits_{i=1}^{n}C_{\sigma,2}^i)$$

$$C_M^{\text{agg}} = 
(\prod\limits_{i=1}^{n}C_{M,1}^i, \prod\limits_{i=1}^{n}C_{M,2}^i)
$$

$$\pi^{\text{agg}} = 
(\prod\limits_{i=1}^{n}\pi_{1}^i, \prod\limits_{i=1}^{n}\pi_{2}^i)
$$

$$avk = \prod\limits_{i=1}^{n}vk_i$$

$$T_{\text{agg}} = (\prod\limits_{i=1}^{n}e(C^i_{M,1}, avk\cdot vk_i^{-1}), \prod\limits_{i=1}^{n}e(C^i_{M,2}, avk\cdot vk_i^{-1}))$$

$$\hat{\sigma} = (C_{\sigma}^{\text{agg}}, C_M^{\text{agg}}, \pi^{\text{agg}}, avk, T_{\text{agg}})$$

## CAggVf($\{vk_i\}^n_{i=1}, \hat{\sigma}$) &rarr; 1 or 0

Compute 
$$avk' = \prod\limits_{i=1}^{n}vk_i$$

Check if 
$$avk'=avk$$

and output 1 if
$$e(C_{\sigma,k}^{\text{agg}}, g_2)e(C_{M,k}^{\text{agg}}, avk^{-1})T_{\text{agg},k}
=e(v_k, \pi^{\text{agg}}_1)e(w_k, \pi^{\text{agg}}_2)$$
for k=1,2

0 otherwise

## LAggOp($\hat{\sigma}, \{(\hat{\sigma_i}, vk_i)\}_{i=1}^n, \hat{\sigma_j}, j\epsilon[n]$) &rarr; $lop_j$

Compute 
$$C_{\sigma, lop_j} = (\prod_{\substack{i=1 \\ i \neq j}}^{n}C_{\sigma,1}^i,
\prod_{\substack{i=1 \\ i \neq j}}^{n}C_{\sigma,2}^i)$$

$$C_{M, lop_j} = (\prod_{\substack{i=1 \\ i \neq j}}^{n}C_{M,1}^i,
\prod_{\substack{i=1 \\ i \neq j}}^{n}C_{M,2}^i)$$

$$\pi_{lop_j} = (\prod_{\substack{i=1 \\ i \neq j}}^{n}\pi_{1}^i,
\prod_{\substack{i=1 \\ i \neq j}}^{n}\pi_{2}^i)$$

$$T_{lop_j} = (\prod_{\substack{i=1 \\ i \neq j}}^{n}e(C_{M,1}^i, avk\cdot vk_i^{-1}),
\prod_{\substack{i=1 \\ i \neq j}}^{n}e(C_{M,2}^i, avk\cdot vk_i^{-1}))$$

Output 
$$lop_j = (C_{\sigma, lop_j}, C_{M, lop_j}, \pi_{lop_j}, T_{lop_j})$$

## LAggVf($vk_j, \hat{\sigma}, lop_j, \hat{\sigma_j}$) &rarr; 1 or 0

Output 1 if
$$e(C_{\sigma, lop_j, k}, g_2)e(C_{M, lop_j, k}, avk^{-1})e(C_{\sigma, k}^j, g_2)e(C_{M, k}^j, vk_j^{-1})T_{lop_j, k}\newline 
= e(v_k,\pi_{lop_j,1})e(w_k,\pi_{lop_j,2})e(v_k,\pi_{1}^j)e(w_k,\pi_{2}^j)
$$
for k=1,2

0 otherwise