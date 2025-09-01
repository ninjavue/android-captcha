#include <jni.h>
#include <string>
#include <opencv2/opencv.hpp>
#include <android/asset_manager_jni.h>
#include <android/log.h>
#include <map>
#include <ctime>
#include <random>
#include <vector>
#include <iterator>
#include <iomanip>
#include <sstream>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <android/asset_manager.h>
#include <cstdlib>

#define LOG_TAG "CaptchaJNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

struct CaptchaData {
    int x, y;
    long expires;
};

static std::map<std::string, CaptchaData> captchaStore;


std::string base64_encode(const std::vector<uchar>& buf) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buf.data(), buf.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::string random_hex(size_t len) {
    std::vector<unsigned char> buf(len);
    RAND_bytes(buf.data(), len);
    std::ostringstream oss;
    for (auto b : buf) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

long now_ms() {
    return static_cast<long>(std::time(nullptr)) * 1000;
}

std::vector<uchar> readAsset(AAssetManager* mgr, const char* filename) {
    std::vector<uchar> buffer;
    AAsset* asset = AAssetManager_open(mgr, filename, AASSET_MODE_BUFFER);
    if (!asset) return buffer;
    off_t len = AAsset_getLength(asset);
    buffer.resize(len);
    AAsset_read(asset, buffer.data(), len);
    AAsset_close(asset);
    return buffer;
}

cv::Mat createJigsawMask(int width, int height, int extra, std::map<std::string, int> directions);


std::vector<std::string> getImageFiles(AAssetManager* mgr) {
    std::vector<std::string> imageFiles;
    AAssetDir* assetDir = AAssetManager_openDir(mgr, "");
    const char* fileName = nullptr;
    while ((fileName = AAssetDir_getNextFileName(assetDir)) != nullptr) {
        std::string name(fileName);
        if (name.size() > 4) {
            std::string ext = name.substr(name.size() - 4);
            if (ext == ".jpg" || ext == ".png") {
                imageFiles.push_back(name);
            }
        }
    }
    AAssetDir_close(assetDir);
    return imageFiles;
}


std::vector<uchar> readRandomAsset(AAssetManager* mgr) {
    std::vector<std::string> images = getImageFiles(mgr);
    if (images.empty()) return {};
    srand(time(nullptr));
    int idx = rand() % images.size();
    return readAsset(mgr, images[idx].c_str());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_uz_csec_captcha_NativeLib_getCaptcha(JNIEnv *env, jobject thiz, jobject assetManager) {
    AAssetManager* mgr = AAssetManager_fromJava(env, assetManager);
    std::vector<uchar> imgBuf = readRandomAsset(mgr);
    if (imgBuf.empty()) {
        LOGD("Image not found in assets!");
        return env->NewStringUTF("{\"error\":\"Image not found\"}");
    }
    cv::Mat image = cv::imdecode(imgBuf, cv::IMREAD_COLOR);
    if (image.empty()) {
        LOGD("Image decode error!");
        return env->NewStringUTF("{\"error\":\"Decode error\"}");
    }
    int imgW = image.cols, imgH = image.rows;
    int puzzleW = 40, puzzleH = 40;
    int extra = 24;
    int maxX = imgW - puzzleW - extra * 2;
    int maxY = imgH - puzzleH - extra * 2;
    std::random_device rd; std::mt19937 gen(rd());
    std::uniform_int_distribution<> xdis(extra, maxX), ydis(extra, maxY);
    int x = xdis(gen), y = ydis(gen);

    int decoyX, decoyY;
    do {
        decoyX = xdis(gen);
        decoyY = ydis(gen);
    } while (std::abs(decoyX - x) < puzzleW || std::abs(decoyY - y) < puzzleH);

    std::vector<std::string> sides = {"top", "right", "bottom", "left"};
    std::map<std::string, int> directions;
    int first = rand() % 2 ? 1 : -1;
    int sameCount = 1;
    directions[sides[0]] = first;
    for (int i = 1; i < 4; ++i) {
        int val = rand() % 2 ? 1 : -1;
        directions[sides[i]] = val;
        if (val == first) sameCount++;
    }
    if (sameCount == 4) {
        directions[sides[3]] *= -1;
    }

    cv::Mat mask = createJigsawMask(puzzleW, puzzleH, extra, directions);

    cv::Mat roi = image(cv::Rect(x - extra, y - extra, mask.cols, mask.rows));
    cv::Mat pieceRGBA(mask.rows, mask.cols, CV_8UC4, cv::Scalar(0,0,0,0)); // to'liq transparent
    for (int i = 0; i < mask.rows; ++i) {
        for (int j = 0; j < mask.cols; ++j) {
            if (mask.at<uchar>(i, j) > 0) {
                cv::Vec3b color = roi.at<cv::Vec3b>(i, j);
                pieceRGBA.at<cv::Vec4b>(i, j) = cv::Vec4b(color[0], color[1], color[2], 255);
            }
        }
    }

    cv::Mat decoyRoi = image(cv::Rect(decoyX - extra, decoyY - extra, mask.cols, mask.rows));
    cv::Mat decoyPieceRGBA(mask.rows, mask.cols, CV_8UC4, cv::Scalar(0,0,0,0));
    for (int i = 0; i < mask.rows; ++i) {
        for (int j = 0; j < mask.cols; ++j) {
            if (mask.at<uchar>(i, j) > 0) {
                cv::Vec3b color = decoyRoi.at<cv::Vec3b>(i, j);
                decoyPieceRGBA.at<cv::Vec4b>(i, j) = cv::Vec4b(color[0], color[1], color[2], 255);
            }
        }
    }

    cv::Mat imageWithHole = image.clone();
    cv::Mat roiMain = imageWithHole(cv::Rect(x - extra, y - extra, mask.cols, mask.rows));
    roi.copyTo(roiMain, 255 - mask);
    for (int i = 0; i < mask.rows; ++i) {
        for (int j = 0; j < mask.cols; ++j) {
            if (mask.at<uchar>(i, j) > 0) {
                cv::Vec4b decoyPixel = decoyPieceRGBA.at<cv::Vec4b>(i, j);
                roiMain.at<cv::Vec3b>(i, j) = cv::Vec3b(decoyPixel[0], decoyPixel[1], decoyPixel[2]);
            }
        }
    }

    std::vector<uchar> bufMain, bufPiece;
    cv::imencode(".png", imageWithHole, bufMain);
    cv::imencode(".png", pieceRGBA, bufPiece);
    std::string mainB64 = base64_encode(bufMain);
    std::string pieceB64 = base64_encode(bufPiece);

    std::string captchaId = random_hex(8);
    captchaStore[captchaId] = {x, y, now_ms() + 30 * 1000};
    std::ostringstream oss;
    oss << "{";
    oss << "\"captchaId\":\"" << captchaId << "\",";
    oss << "\"mainImage\":\"" << mainB64 << "\",";
    oss << "\"puzzlePiece\":\"" << pieceB64 << "\"";
    oss << "}";
    return env->NewStringUTF(oss.str().c_str());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_uz_csec_captcha_NativeLib_verifyCaptcha(JNIEnv *env, jobject thiz, jstring jcaptchaId, jint x, jint y, jfloat scaleX, jfloat scaleY) {
    const char *captchaId = env->GetStringUTFChars(jcaptchaId, nullptr);
    auto it = captchaStore.find(captchaId);
    if (it == captchaStore.end() || it->second.expires < now_ms()) {
        captchaStore.erase(captchaId);
        env->ReleaseStringUTFChars(jcaptchaId, captchaId);
        return env->NewStringUTF("{\"success\":false}");
    }
    int storedX = it->second.x, storedY = it->second.y;
    captchaStore.erase(captchaId);
    env->ReleaseStringUTFChars(jcaptchaId, captchaId);

    float magnetDistance = 5 * scaleX;
    float magnetDistanceY = 5 * scaleY;
    bool magnetApplied = false;

    if (std::abs(storedX - x) <= magnetDistance && std::abs(storedY - y) <= magnetDistanceY) {
        x = storedX;
        y = storedY;
        magnetApplied = true;
    }

    int tolerance = 15;
    bool ok = std::abs(storedX - x) <= tolerance && std::abs(storedY - y) <= tolerance;

    std::ostringstream oss;
    oss << "{";
    oss << "\"success\":" << (ok ? "true" : "false") << ",";
    oss << "\"magnetApplied\":" << (magnetApplied ? "true" : "false") << ",";
    oss << "\"adjustedX\":" << x << ",";
    oss << "\"adjustedY\":" << y;
    oss << "}";
    return env->NewStringUTF(oss.str().c_str());
}

cv::Mat createJigsawMask(int width, int height, int extra, std::map<std::string, int> directions) {
    int w = width + extra * 2;
    int h = height + extra * 2;
    cv::Mat mask = cv::Mat::zeros(h, w, CV_8UC1);

    std::vector<cv::Point> contour;
    int knobW = width * 0.3, knobH = height * 0.3;
    int baseX = extra, baseY = extra;
    int centerX = baseX + width / 2, centerY = baseY + height / 2;

    contour.push_back(cv::Point(baseX, baseY));
    contour.push_back(cv::Point(centerX - knobW/2, baseY));
    if (directions["top"] == 1) {
        contour.push_back(cv::Point(centerX - knobW/4, baseY - knobH));
        contour.push_back(cv::Point(centerX + knobW/4, baseY - knobH));
    } else {
        contour.push_back(cv::Point(centerX - knobW/4, baseY + knobH * 0.7));
        contour.push_back(cv::Point(centerX + knobW/4, baseY + knobH * 0.7));
    }
    contour.push_back(cv::Point(centerX + knobW/2, baseY));
    contour.push_back(cv::Point(baseX + width, baseY));
    // O'ng tomon
    contour.push_back(cv::Point(baseX + width, centerY - knobH/2));
    if (directions["right"] == 1) {
        contour.push_back(cv::Point(baseX + width + knobW, centerY - knobH/4));
        contour.push_back(cv::Point(baseX + width + knobW, centerY + knobH/4));
    } else {
        contour.push_back(cv::Point(baseX + width - knobW * 0.7, centerY - knobH/4));
        contour.push_back(cv::Point(baseX + width - knobW * 0.7, centerY + knobH/4));
    }
    contour.push_back(cv::Point(baseX + width, centerY + knobH/2));
    contour.push_back(cv::Point(baseX + width, baseY + height));
    // Pastki tomon
    contour.push_back(cv::Point(centerX + knobW/2, baseY + height));
    if (directions["bottom"] == 1) {
        contour.push_back(cv::Point(centerX + knobW/4, baseY + height + knobH));
        contour.push_back(cv::Point(centerX - knobW/4, baseY + height + knobH));
    } else {
        contour.push_back(cv::Point(centerX + knobW/4, baseY + height - knobH * 0.7));
        contour.push_back(cv::Point(centerX - knobW/4, baseY + height - knobH * 0.7));
    }
    contour.push_back(cv::Point(centerX - knobW/2, baseY + height));
    contour.push_back(cv::Point(baseX, baseY + height));
    // Chap tomon
    contour.push_back(cv::Point(baseX, centerY + knobH/2));
    if (directions["left"] == 1) {
        contour.push_back(cv::Point(baseX - knobW, centerY + knobH/4));
        contour.push_back(cv::Point(baseX - knobW, centerY - knobH/4));
    } else {
        contour.push_back(cv::Point(baseX + knobW * 0.7, centerY + knobH/4));
        contour.push_back(cv::Point(baseX + knobW * 0.7, centerY - knobH/4));
    }
    contour.push_back(cv::Point(baseX, centerY - knobH/2));
    contour.push_back(cv::Point(baseX, baseY));

    std::vector<std::vector<cv::Point>> contours = {contour};
    cv::fillPoly(mask, contours, cv::Scalar(255));
    return mask;
}