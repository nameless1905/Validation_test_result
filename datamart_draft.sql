-- =====================================================================
-- ЧЕРНОВИК: DATA MART для ML-пайплайна автовалидации CBC
-- База: PostgreSQL (соответствует дампу вашей ЛИС)
-- Статус: черновик для последующей корректировки. Места, требующие
-- уточнения, помечены как TODO/PLACEHOLDER.
-- =====================================================================

-- Для хэширования при псевдонимизации (digest/hmac)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS mart;

-- =====================================================================
-- 0. КОНФИГУРАЦИЯ / СОЛЬ ДЛЯ ПСЕВДОНИМИЗАЦИИ
-- =====================================================================
-- TODO: хранить соль в защищённом vault (HashiCorp Vault / AWS KMS),
-- а не в таблице БД. Здесь — временная заглушка для черновика.
CREATE TABLE IF NOT EXISTS mart.pseudonymization_config (
    salt_value text NOT NULL
);
-- INSERT INTO mart.pseudonymization_config VALUES ('ЗАМЕНИТЬ_НА_РЕАЛЬНУЮ_СОЛЬ');


-- =====================================================================
-- 1. СПРАВОЧНИКИ (dimension tables)
-- =====================================================================

-- --- 1.1 Показатели (WBC, PLT, HGB и т.д.) с нормализованными кодами
CREATE TABLE IF NOT EXISTS mart.dim_measureparameter (
    measureparameter_id   uuid PRIMARY KEY,
    source_code            text,          -- measureparameter.code как есть в ЛИС
    source_name             text,          -- measureparameter.name как есть (может быть кириллица/разночтения)
    normalized_code          text,          -- TODO: заполнить вручную/через маппинг-таблицу: WBC, PLT, HGB...
    measureassay_id           uuid,
    measuringunit_id           uuid,
    measuringunit_name          text
);

INSERT INTO mart.dim_measureparameter
    (measureparameter_id, source_code, source_name, normalized_code, measureassay_id, measuringunit_id, measuringunit_name)
SELECT
    mp.id,
    mp.code,
    mp.name,
    NULL,  -- TODO: подставить normalized_code через CASE/справочник маппинга source_code -> WBC/PLT/...
    mp.measureassay_id,
    mp.measuringunit_id,
    mu.name
FROM public.measureparameter mp
LEFT JOIN public.measuringunits mu ON mu.id = mp.measuringunit_id
WHERE mp.deleted = false
ON CONFLICT (measureparameter_id) DO NOTHING;


-- --- 1.2 Анализаторы
CREATE TABLE IF NOT EXISTS mart.dim_analyzer (
    analyser_id     uuid PRIMARY KEY,
    analyzer_name    text,
    normalized_model  text   -- TODO: нормализовать написание модели (Mindray CAL8000 и т.п.)
);

INSERT INTO mart.dim_analyzer (analyser_id, analyzer_name, normalized_model)
SELECT id, name, name  -- TODO: заменить normalized_model на результат нормализации
FROM public.analyser
WHERE deleted = false
ON CONFLICT (analyser_id) DO NOTHING;


-- --- 1.3 Пороги/конфигурация метода (включая дельта-чек)
CREATE TABLE IF NOT EXISTS mart.dim_method_thresholds (
    method_id          uuid PRIMARY KEY,
    measureparameter_id uuid,
    analyser_id          uuid,
    reagent_id             uuid,
    minvalue                 double precision,
    maxvalue                  double precision,
    maxdeviatecoeff            double precision,  -- порог дельта-чека, уже сконфигурирован в ЛИС
    autovalidation                boolean,
    snapshot_ts                    timestamp DEFAULT now()  -- версионирование: пороги могут меняться со временем
);

INSERT INTO mart.dim_method_thresholds
    (method_id, measureparameter_id, analyser_id, reagent_id, minvalue, maxvalue, maxdeviatecoeff, autovalidation)
SELECT
    m.id,
    m.measureparameter_id,
    m.analyser_id,
    m.reagent_id,
    m.minvalue,
    m.maxvalue,
    m.maxdeviatecoeff,
    m.autovalidation
FROM public.method m
WHERE m.deleted = false
ON CONFLICT (method_id) DO NOTHING;


-- --- 1.4 Реагенты / лоты
CREATE TABLE IF NOT EXISTS mart.dim_reagent_lot (
    reagentlot_id    uuid PRIMARY KEY,
    reagent_id         uuid,
    reagent_name         text,
    lotnumber_hash          text,   -- хэшируем, если лот покидает защищённый контур
    expirationdate           timestamp,
    isactive                   boolean
);

INSERT INTO mart.dim_reagent_lot
    (reagentlot_id, reagent_id, reagent_name, lotnumber_hash, expirationdate, isactive)
SELECT
    rl.id,
    rl.reagent_id,
    r.name,
    encode(digest(rl.lotnumber || (SELECT salt_value FROM mart.pseudonymization_config LIMIT 1), 'sha256'), 'hex'),
    rl.expirationdate,
    rl.isactive
FROM public.reagentlots rl
LEFT JOIN public.reagents r ON r.id = rl.reagent_id
WHERE rl.deleted = false
ON CONFLICT (reagentlot_id) DO NOTHING;


-- =====================================================================
-- 2. ПСЕВДОНИМИЗИРОВАННЫЙ РЕЕСТР ПАЦИЕНТОВ
-- =====================================================================
CREATE TABLE IF NOT EXISTS mart.dim_patient (
    patient_id             uuid PRIMARY KEY,      -- внутри защищённого контура, для join
    patient_pseudo_id        text UNIQUE NOT NULL,  -- то, что уходит во внешний/ML-датасет
    birthdate                  date,
    age_years_snapshot            integer,          -- TODO: пересчитывать на момент результата, а не статично
    gender_code                    integer,
    sex_normalized                    text            -- TODO: расшифровать gender через enum-справочник
);

INSERT INTO mart.dim_patient (patient_id, patient_pseudo_id, birthdate, gender_code)
SELECT
    p.id,
    'p_' || substr(encode(digest(p.id::text || (SELECT salt_value FROM mart.pseudonymization_config LIMIT 1), 'sha256'), 'hex'), 1, 12),
    p.birthdate::date,
    p.gender
FROM public.patients p
WHERE p.deleted = false
ON CONFLICT (patient_id) DO NOTHING;


-- =====================================================================
-- 3. ТАБЛИЦА ФАКТОВ — один результат-показатель на строку (сырой уровень)
-- =====================================================================
CREATE TABLE IF NOT EXISTS mart.fact_measurement_raw (
    id                    uuid DEFAULT uuid_generate_v1() PRIMARY KEY,
    measurecontext_id       uuid,               -- ссылка на источник (внутри контура)
    orderline_id              uuid,
    sample_id                   uuid,
    order_id                     uuid,
    patient_pseudo_id              text,
    measureparameter_id             uuid,
    normalized_code                    text,
    value                                double precision,
    unit                                  text,
    ref_min                                double precision,
    ref_max                                 double precision,
    flag                                     text,           -- 'L'/'H'/NULL, из lessflag/moreflag
    resultrefcharstatus_raw                    integer,       -- TODO: расшифровать через enum-таблицы
    was_entered_manually                         boolean,
    collected_at                                   timestamp,
    method_id                                        uuid,
    analyser_id                                        uuid,
    reagentlot_id                                        uuid,
    created_at                                              timestamp DEFAULT now()
);

-- ETL-заполнение сырого уровня фактов
-- TODO: заменить фильтр по assay.code на реальные коды вашей CBC-панели
INSERT INTO mart.fact_measurement_raw (
    measurecontext_id, orderline_id, sample_id, order_id, patient_pseudo_id,
    measureparameter_id, normalized_code, value, unit, ref_min, ref_max, flag,
    resultrefcharstatus_raw, was_entered_manually, collected_at, method_id, analyser_id, reagentlot_id
)
SELECT
    mc.id,
    ol.id,
    s.id,
    o.id,
    dp.patient_pseudo_id,
    mc.measureparameter_id,
    dmp.normalized_code,
    mc.numericvalue,
    dmp.measuringunit_name,
    mc.normalminvalue,
    mc.normalmaxvalue,
    CASE
        WHEN mc.lessflag = true THEN 'L'
        WHEN mc.moreflag = true THEN 'H'
        ELSE NULL
    END AS flag,
    mc.resultrefcharstatus,
    mc.wasenteredmanually,
    s.samplingtimestamp,
    mc.method_id,
    mth.analyser_id,
    mth.reagent_id   -- TODO: связать конкретный лот (reagentlots), а не только reagent_id — нужна доп. логика выбора активного лота на дату
FROM public.measurecontext mc
JOIN public.orderline ol       ON ol.id = mc.measureorderline_id
JOIN public.sample s            ON s.id = ol.sample_id
JOIN public.orders o             ON o.id = ol.order_id
JOIN mart.dim_patient dp          ON dp.patient_id = o.patient_id
JOIN public.assay a                ON a.id = ol.assay_id
LEFT JOIN mart.dim_measureparameter dmp ON dmp.measureparameter_id = mc.measureparameter_id
LEFT JOIN mart.dim_method_thresholds mth ON mth.method_id = mc.method_id
WHERE mc.deleted IS NOT TRUE  -- TODO: проверить, есть ли столбец deleted у measurecontext в вашей версии
  AND a.code IN ('PLACEHOLDER_CBC_ASSAY_CODE')  -- TODO: подставить реальные коды ОАК из вашей assay
  AND s.samplingtimestamp IS NOT NULL;


-- =====================================================================
-- 4. ТАБЛИЦА ФАКТОВ — свёрнутая по кейсу (case-level, готова для сериализации в JSON)
-- =====================================================================
CREATE TABLE IF NOT EXISTS mart.fact_cbc_case (
    case_id              uuid DEFAULT uuid_generate_v1() PRIMARY KEY,
    order_id                uuid,
    orderline_id               uuid,
    sample_id                     uuid,
    patient_pseudo_id                text,
    collected_at                        timestamp,
    age_years                             integer,
    sex                                     text,
    analyzer_model                          text,
    reagentlot_hash                            text,
    indices_json                                 jsonb,     -- агрегированные показатели одним объектом
    rule_verdict                                    text,     -- из orderline.state (после расшифровки)
    rule_alert_flag                                    boolean,
    rule_alert_message_raw                                text,
    created_at                                              timestamp DEFAULT now()
);

-- ETL: агрегация нескольких строк fact_measurement_raw в один JSON-объект на кейс
INSERT INTO mart.fact_cbc_case (
    case_id, order_id, orderline_id, sample_id, patient_pseudo_id, collected_at,
    age_years, sex, analyzer_model, reagentlot_hash, indices_json,
    rule_verdict, rule_alert_flag, rule_alert_message_raw
)
SELECT
    uuid_generate_v1(),
    fr.order_id,
    fr.orderline_id,
    fr.sample_id,
    fr.patient_pseudo_id,
    fr.collected_at,
    dp.age_years_snapshot,   -- TODO: пересчитать возраст на collected_at, а не брать статичный снапшот
    dp.sex_normalized,
    da.normalized_model,
    drl.lotnumber_hash,
    jsonb_object_agg(
        fr.normalized_code,
        jsonb_build_object(
            'value', fr.value,
            'unit', fr.unit,
            'ref_range', jsonb_build_array(fr.ref_min, fr.ref_max),
            'flag', fr.flag
        )
    ) AS indices_json,
    ol.state::text,          -- TODO: заменить на расшифрованный текстовый вердикт через enum-справочник
    ol.alert,
    ol.alertmessage
FROM mart.fact_measurement_raw fr
JOIN public.orderline ol   ON ol.id = fr.orderline_id
LEFT JOIN mart.dim_patient dp ON dp.patient_pseudo_id = fr.patient_pseudo_id
LEFT JOIN mart.dim_analyzer da ON da.analyser_id = fr.analyser_id
LEFT JOIN mart.dim_reagent_lot drl ON drl.reagentlot_id = fr.reagentlot_id
GROUP BY
    fr.order_id, fr.orderline_id, fr.sample_id, fr.patient_pseudo_id, fr.collected_at,
    dp.age_years_snapshot, dp.sex_normalized, da.normalized_model, drl.lotnumber_hash,
    ol.state, ol.alert, ol.alertmessage;


-- =====================================================================
-- 5. ИСТОРИЯ И ДЕЛЬТА-ЧЕК (предрасчитанные, отдельная таблица)
-- =====================================================================
CREATE TABLE IF NOT EXISTS mart.fact_patient_history (
    case_id             uuid REFERENCES mart.fact_cbc_case(case_id),
    historical_results     jsonb,   -- последние N результатов по пациенту (до текущего collected_at)
    delta_check                jsonb    -- {"WBC_delta_pct": ..., "PLT_delta_pct": ...}
);

-- ETL: для каждого текущего кейса ищем до 5 предыдущих результатов того же пациента
-- по тем же показателям и считаем дельту по последнему из них.
-- TODO: логика дельты сейчас упрощённая (по одному показателю за раз через LATERAL) —
-- проверить производительность на реальном объёме данных, при необходимости
-- переписать через оконные функции (LAG) по предварительно развёрнутой таблице.

INSERT INTO mart.fact_patient_history (case_id, historical_results, delta_check)
SELECT
    fc.case_id,
    (
        SELECT jsonb_agg(h)
        FROM (
            SELECT jsonb_build_object(
                       'collected_at', prev.collected_at,
                       'indices', prev.indices_json
                   ) AS h
            FROM mart.fact_cbc_case prev
            WHERE prev.patient_pseudo_id = fc.patient_pseudo_id
              AND prev.collected_at < fc.collected_at
            ORDER BY prev.collected_at DESC
            LIMIT 5   -- TODO: подобрать разумное окно истории (см. обсуждение лимита контекста TabLLM)
        ) sub
    ) AS historical_results,
    (
        SELECT jsonb_object_agg(key || '_delta_pct', delta_pct)
        FROM (
            SELECT
                key,
                ROUND(
                    ((fc.indices_json -> key ->> 'value')::numeric
                     - (last_val.indices_json -> key ->> 'value')::numeric)
                    / NULLIF((last_val.indices_json -> key ->> 'value')::numeric, 0) * 100,
                    1
                ) AS delta_pct
            FROM jsonb_object_keys(fc.indices_json) AS key
            CROSS JOIN LATERAL (
                SELECT prev.indices_json
                FROM mart.fact_cbc_case prev
                WHERE prev.patient_pseudo_id = fc.patient_pseudo_id
                  AND prev.collected_at < fc.collected_at
                ORDER BY prev.collected_at DESC
                LIMIT 1
            ) last_val
            WHERE last_val.indices_json ? key
        ) deltas
    ) AS delta_check
FROM mart.fact_cbc_case fc
ON CONFLICT DO NOTHING;


-- =====================================================================
-- 6. ИТОГОВОЕ ПРЕДСТАВЛЕНИЕ — готовый вид для выгрузки в ML-датасет
-- =====================================================================
CREATE OR REPLACE VIEW mart.v_ml_case_export AS
SELECT
    fc.case_id,
    fc.collected_at,
    fc.patient_pseudo_id,
    fc.age_years,
    fc.sex,
    fc.analyzer_model,
    fc.reagentlot_hash,
    fc.indices_json,
    fc.rule_verdict,
    fc.rule_alert_flag,
    fc.rule_alert_message_raw,
    ph.historical_results,
    ph.delta_check
FROM mart.fact_cbc_case fc
LEFT JOIN mart.fact_patient_history ph ON ph.case_id = fc.case_id;

-- Пример выгрузки одного кейса в формате, близком к целевой схеме case:
-- SELECT row_to_json(v) FROM mart.v_ml_case_export v WHERE case_id = '...';


-- =====================================================================
-- СПИСОК TODO ПЕРЕД ЗАПУСКОМ В ПРОДЕ (собрано из комментариев выше)
-- =====================================================================
-- 1. Соль псевдонимизации вынести в защищённое хранилище, не в таблицу БД.
-- 2. Заполнить normalized_code в dim_measureparameter (маппинг WBC/PLT/...).
-- 3. Заполнить normalized_model в dim_analyzer (нормализация названий).
-- 4. Подставить реальные коды CBC-assay вместо PLACEHOLDER_CBC_ASSAY_CODE.
-- 5. Расшифровать orderline.state и measurecontext.resultrefcharstatus через
--    enumerationliteral/enumerationliteralcode/enumrefcharliteral.
-- 6. Пересчитывать age_years на дату collected_at, а не хранить статичный снапшот.
-- 7. Проверить наличие столбца deleted у measurecontext в вашей версии схемы.
-- 8. Продумать логику выбора актуального лота реагента на дату результата
--    (сейчас reagent_id, а не конкретный reagentlot_id, берётся из method).
-- 9. Протестировать производительность блока дельта-чека на реальном объёме
--    и при необходимости переписать через оконные функции.
-- 10. Добавить обработку instrument_flags/scattergram/morphology, когда будет
--     подтверждено, откуда их реально брать (autocomment или другой источник).
