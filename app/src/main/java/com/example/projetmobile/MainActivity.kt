package com.example.projetmobile

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    private val BASE_URL = "http://10.0.2.2:80/api/v1"
    private val client = OkHttpClient()
    private val executor = Executors.newFixedThreadPool(4)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val logView = findViewById<TextView>(R.id.logView)
        val btnNormal = findViewById<Button>(R.id.btnNormal)
        val btnBrute = findViewById<Button>(R.id.btnBrute)
        val btnSpike = findViewById<Button>(R.id.btnSpike)
        val btnEnum = findViewById<Button>(R.id.btnEnum)

        btnNormal.setOnClickListener {
            executor.execute {
                for (i in 1..20) {
                    sendRequest("GET", "/products", null)
                    sendRequest("GET", "/user/profile", null)
                    Thread.sleep(500)
                }
                runOnUiThread { logView.append("\n[✓] Trafic normal envoyé") }
            }
        }

        btnBrute.setOnClickListener {
            executor.execute {
                val body = """{"username":"admin","password":"wrong"}"""
                for (i in 1..30) {
                    sendRequest("POST", "/login", body)
                    Thread.sleep(200)
                }
                runOnUiThread { logView.append("\n[!] Brute force simulé (30 tentatives)") }
            }
        }

        btnSpike.setOnClickListener {
            executor.execute {
                for (i in 1..50) {
                    sendRequest("GET", "/products", null)
                }
                runOnUiThread { logView.append("\n[!] Spike envoyé (50 requêtes rapides)") }
            }
        }

        btnEnum.setOnClickListener {
            executor.execute {
                val endpoints = listOf("/user/1", "/user/2", "/user/3", "/admin", "/config", "/backup")
                for (ep in endpoints) {
                    sendRequest("GET", ep, null)
                    Thread.sleep(300)
                }
                runOnUiThread { logView.append("\n[!] Énumération effectuée") }
            }
        }
    }

    private fun sendRequest(method: String, path: String, jsonBody: String?) {
        try {
            val request = if (method == "POST" && jsonBody != null) {
                val body = jsonBody.toRequestBody("application/json".toMediaType())
                Request.Builder().url("$BASE_URL$path").post(body).build()
            } else {
                Request.Builder().url("$BASE_URL$path").get().build()
            }
            val response = client.newCall(request).execute()
            android.util.Log.d("TRAFFIC", "✅ ${method} ${path} → ${response.code}")
            response.close()
        } catch (e: Exception) {
            android.util.Log.e("TRAFFIC", "❌ Erreur: ${e.message}")
        }
    }
}