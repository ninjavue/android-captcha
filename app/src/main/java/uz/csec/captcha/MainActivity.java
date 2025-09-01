package uz.csec.captcha;

import android.annotation.SuppressLint;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import org.json.JSONObject;

public class MainActivity extends AppCompatActivity {
    NativeLib nativeLib = new NativeLib();
    private String captchaId;
    private boolean isDragging = false;
    private float scaleX = 1.0f;
    private float scaleY = 1.0f;
    private ImageView mainImage;
    private ImageView puzzlePiece;
    private TextView resultText;

    @SuppressLint("ClickableViewAccessibility")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mainImage = findViewById(R.id.main_image);
        puzzlePiece = findViewById(R.id.puzzle_piece);
        ImageView refreshBtn = findViewById(R.id.refresh_icon);
        resultText = findViewById(R.id.result_text);

        refreshBtn.setOnClickListener(v -> loadCaptcha(true));
        loadCaptcha(true);
    }

    @SuppressLint("ClickableViewAccessibility")
    private void loadCaptcha(boolean hideResultText) {
        if (hideResultText) {
            resultText.setVisibility(View.GONE);
        }

        try {
            String json = nativeLib.getCaptcha(getAssets());
            JSONObject obj = new JSONObject(json);
            captchaId = obj.getString("captchaId");
            String mainImageB64 = obj.getString("mainImage");
            String puzzlePieceB64 = obj.getString("puzzlePiece");

            byte[] mainBytes = Base64.decode(mainImageB64, Base64.DEFAULT);
            byte[] pieceBytes = Base64.decode(puzzlePieceB64, Base64.DEFAULT);
            Bitmap mainBmp = BitmapFactory.decodeByteArray(mainBytes, 0, mainBytes.length);
            Bitmap pieceBmp = BitmapFactory.decodeByteArray(pieceBytes, 0, pieceBytes.length);

            mainImage.setImageBitmap(mainBmp);
            puzzlePiece.setImageBitmap(pieceBmp);

            ViewTreeObserver vto = mainImage.getViewTreeObserver();
            vto.addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() {
                @Override
                public boolean onPreDraw() {
                    if (mainImage.getWidth() > 0 && mainImage.getHeight() > 0) {
                        scaleX = mainBmp.getWidth() / (float) mainImage.getWidth();
                        scaleY = mainBmp.getHeight() / (float) mainImage.getHeight();

                        puzzlePiece.setX(mainImage.getX() + mainImage.getWidth() / 2f - puzzlePiece.getWidth() / 2f);
                        puzzlePiece.setY(mainImage.getY() + mainImage.getHeight() + 32);
                        mainImage.getViewTreeObserver().removeOnPreDrawListener(this);
                    }
                    return true;
                }
            });

            puzzlePiece.setOnTouchListener(new View.OnTouchListener() {
                float dX, dY;

                @SuppressLint("ClickableViewAccessibility")
                @Override
                public boolean onTouch(View v, MotionEvent event) {
                    switch (event.getAction()) {
                        case MotionEvent.ACTION_DOWN:
                            dX = v.getX() - event.getRawX();
                            dY = v.getY() - event.getRawY();
                            isDragging = true;
                            return true;
                        case MotionEvent.ACTION_MOVE:
                            if (isDragging) {
                                float newX = event.getRawX() + dX;
                                float newY = event.getRawY() + dY;
                                newX = Math.max(mainImage.getX(), Math.min(newX, mainImage.getX() + mainImage.getWidth() - v.getWidth()));
                                newY = Math.max(mainImage.getY(), Math.min(newY, mainImage.getY() + mainImage.getHeight() - v.getHeight()));
                                v.setX(newX);
                                v.setY(newY);
                            }
                            return true;
                        case MotionEvent.ACTION_UP:
                            isDragging = false;
                            final int extra = 24;
                            float px = (puzzlePiece.getX() - mainImage.getX()) * scaleX + extra;
                            float py = (puzzlePiece.getY() - mainImage.getY()) * scaleY + extra;

                            String resultJson = nativeLib.verifyCaptcha(captchaId, Math.round(px), Math.round(py), scaleX, scaleY);
                            try {
                                JSONObject resultObj = new JSONObject(resultJson);

                                boolean success = resultObj.getBoolean("success");
                                boolean magnetApplied = resultObj.getBoolean("magnetApplied");
                                int adjustedX = resultObj.getInt("adjustedX");
                                int adjustedY = resultObj.getInt("adjustedY");

                                if (magnetApplied) {
                                    puzzlePiece.setX(mainImage.getX() + (adjustedX - extra) / scaleX);
                                    puzzlePiece.setY(mainImage.getY() + (adjustedY - extra) / scaleY);
                                }
                                if (success) {
                                    resultText.setText("true success");
                                    resultText.setBackgroundColor(getColor(R.color.success));
                                    resultText.setVisibility(View.VISIBLE);
                                } else {
                                    resultText.setText("false incorrect-answer");
                                    resultText.setBackgroundColor(getColor(R.color.danger));
                                    resultText.setVisibility(View.VISIBLE);
                                }
                            } catch (Exception e) {
                                resultText.setText("false incorrect-answer");
                                resultText.setVisibility(View.VISIBLE);
                            }

                            new Handler(Looper.getMainLooper()).postDelayed(() -> loadCaptcha(false), 500);
                            return true;
                    }
                    return false;
                }
            });
        } catch (Exception e) {
            resultText.setText("false incorrect-answer");
            resultText.setVisibility(View.VISIBLE);
        }
    }
}