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

SELECT encode(gen_random_bytes(32), 'hex');
INSERT INTO mart.pseudonymization_config VALUES ('bc7b923149461aec845d9edcb754dd2f221cfb31d3522f2015722bd47492a59c');



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





DROP TABLE IF EXISTS mart.dim_patient CASCADE;
 
CREATE TABLE mart.dim_patient (
    patient_pseudo_id      text PRIMARY KEY,
    natural_key_hash          text NOT NULL,   -- технический ключ дедупликации, для внутренней сверки
    order_ids                    uuid[] NOT NULL,  -- ВСЕ orders.id, схлопнувшиеся в этого пациента
    birthdate                       date,
    sex_normalized                    text,
    orders_matched_count                 integer NOT NULL,
    needs_manual_review                     boolean DEFAULT false,  -- см. пояснение по порогу ниже
    created_at                                  timestamp DEFAULT now()
);
 
CREATE UNIQUE INDEX IF NOT EXISTS uq_dim_patient_natural_key ON mart.dim_patient (natural_key_hash);
CREATE INDEX IF NOT EXISTS idx_dim_patient_order_ids ON mart.dim_patient USING gin (order_ids);
 
 
-- =====================================================================
-- ЗАПОЛНЕНИЕ — дедупликация всех orders по естественному ключу (ФИО+ДР)
-- =====================================================================
 
WITH normalized_orders AS (
    SELECT
        o.id AS order_id,
        lower(trim(o.firstname))                 AS fn,
        lower(trim(o.lastname))                    AS ln,
        lower(trim(coalesce(o.middlename, '')))      AS mn,
        o.birthdate::date                              AS bd,
        o.sex                                            AS sex_raw
    FROM public.orders o
    WHERE o.deleted = false
      AND o.firstname IS NOT NULL
      AND o.lastname IS NOT NULL
      AND o.birthdate IS NOT NULL   -- без даты рождения естественный ключ ненадёжен, такие заказы исключаем
),
grouped AS (
    SELECT
        fn, ln, mn, bd,
        mode() WITHIN GROUP (ORDER BY sex_raw) AS sex_mode,
        array_agg(order_id ORDER BY order_id) AS order_ids,
        count(*) AS orders_matched_count
    FROM normalized_orders
    GROUP BY fn, ln, mn, bd
)
INSERT INTO mart.dim_patient (
    patient_pseudo_id, natural_key_hash, order_ids,
    birthdate, sex_normalized, orders_matched_count, needs_manual_review
)
SELECT
    'p_' || substr(
        encode(
            digest(
                fn || '|' || ln || '|' || mn || '|' || bd::text
                || (SELECT salt_value FROM mart.pseudonymization_config LIMIT 1),
                'sha256'
            ),
            'hex'
        ), 1, 12
    ) AS patient_pseudo_id,
    encode(digest(fn || '|' || ln || '|' || mn || '|' || bd::text, 'sha256'), 'hex') AS natural_key_hash,
    order_ids,
    bd,
    sex_mode::text,   -- TODO: расшифровать через enum-справочник вместо сырого кода
    orders_matched_count,
    -- Флаг НЕ означает "что-то не так" сам по себе — множественные заказы это
    -- норма (повторные визиты). Это эвристика для приоритизации выборочной
    -- ручной проверки на предмет ложного схлопывания РАЗНЫХ людей с
    -- одинаковыми ФИО+ДР. Порог 15 — начальный, подберите по факту
    -- распределения (см. диагностику ниже).
    orders_matched_count > 15
FROM grouped
ON CONFLICT (natural_key_hash) DO NOTHING;
 





-- =====================================================================
-- Связка таблицы фактов с dim_patient через orders
-- =====================================================================
 
-- =====================================================================
-- 1. Мостовая таблица: order_id -> patient_pseudo_id
-- Разворачиваем order_ids[] из dim_patient в обычные строки с
-- обычным индексируемым uuid. Это на порядок быстрее прямого join'а
-- через ANY(order_ids)/@> при таком объёме данных (10М заказов).
-- =====================================================================
 
DROP TABLE IF EXISTS mart.patient_order_map;
 
CREATE TABLE mart.patient_order_map (
    order_id           uuid PRIMARY KEY,
    patient_pseudo_id    text NOT NULL REFERENCES mart.dim_patient (patient_pseudo_id)
);
 
INSERT INTO mart.patient_order_map (order_id, patient_pseudo_id)
SELECT
    unnest(dp.order_ids) AS order_id,
    dp.patient_pseudo_id
FROM mart.dim_patient dp;
 
CREATE INDEX IF NOT EXISTS idx_patient_order_map_pseudo ON mart.patient_order_map (patient_pseudo_id);
 
-- Проверка: количество строк моста должно совпадать с суммой orders_matched_count в dim_patient
SELECT
    (SELECT count(*) FROM mart.patient_order_map) AS map_rows,
    (SELECT sum(orders_matched_count) FROM mart.dim_patient) AS expected_rows;
 
 




-- =====================================================================
-- 3. ТАБЛИЦА ФАКТОВ — один результат-показатель на строку (сырой уровень)
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


CREATE TABLE IF NOT EXISTS mart.fact_measurement_raw (
    id                    uuid DEFAULT uuid_generate_v1() PRIMARY KEY,
    measurecontext_id       uuid,               -- ссылка на источник (внутри контура)
    orderline_id              uuid,
                     
    order_id                     uuid,
    patient_pseudo_id              text,
    measureparameter_id             uuid,
    assay_id                        uuid,
    assay_name                      text,
    assay_standardcode              text,

    parametr_name                   text,
    
    value                           double precision,

    unit                                  text,
    ref_min                                double precision,
    ref_max                                 double precision,
    flag                                     text,           -- 'L'/'H'/NULL, из lessflag/moreflag
    resultrefcharstatus_raw                    integer,       -- TODO: расшифровать через enum-таблицы
    was_entered_manually                         boolean,
    
    method_id                                        uuid,
    method_name                                        text,
    analyser_id                                        uuid,
    analyser_name                                      text,
    
    created_at                                              timestamp DEFAULT now()
);

-- ETL-заполнение сырого уровня фактов
-- TODO: заменить фильтр по assay.code на реальные коды вашей CBC-панели
INSERT INTO mart.fact_measurement_raw (
    measurecontext_id, orderline_id, order_id, patient_pseudo_id,
    measureparameter_id,  assay_id , assay_name, assay_standardcode, parametr_name,value, unit,ref_min, ref_max, flag,           -- 'L'/'H'/NULL, из lessflag/moreflag
    resultrefcharstatus_raw,       
    was_entered_manually ,
    
    method_id  ,
    method_name  ,
    analyser_id    ,
    analyser_name 
    
)
SELECT
    mc.id,
    ol.id,
    
    o.id,
    pat.patient_pseudo_id,
    mc.measureparameter_id,
    a.id,
    a.name,
    a.standardcode,

    dmp.name,
    
    mc.numericvalue,
    munit.name,
    mc.normalminvalue,
    mc.normalmaxvalue,
    CASE
        WHEN mc.lessflag = true THEN 'L'
        WHEN mc.moreflag = true THEN 'H'
        ELSE NULL
    END AS flag,
    mc.resultrefcharstatus,
    mc.wasenteredmanually,
   
    mc.method_id,
    mth.name,
    mth.analyser_id,
    an.name  -- TODO: связать конкретный лот (reagentlots), а не только reagent_id — нужна доп. логика выбора активного лота на дату
FROM public.measurecontext mc
JOIN public.orderline ol       ON ol.id = mc.measureorderline_id

JOIN public.orders o             ON o.id = ol.order_id
left join mart.patient_order_map pat  on pat.order_id = o.id

JOIN public.assay a                ON a.id = ol.assay_id
LEFT JOIN public.measureparameter dmp ON dmp.id = mc.measureparameter_id
LEFT JOIN public.measuringunits munit ON dmp.measuringunit_id = munit.id
LEFT JOIN  public.method mth ON mth.id = mc.method_id
left join public.analyser an on an.id = mth.analyser_id
WHERE mc.deleted IS NOT TRUE  -- TODO: проверить, есть ли столбец deleted у measurecontext в вашей версии
 


-- =====================================================================
-- 4. ТАБЛИЦА ФАКТОВ — свёрнутая по кейсу (case-level, готова для сериализации в JSON)
-- =====================================================================
CREATE TABLE IF NOT EXISTS mart.fact_cbc_case (
    case_id              uuid DEFAULT uuid_generate_v1() PRIMARY KEY,
    order_id                uuid,
    orderline_id               uuid,
    
    patient_pseudo_id                text,
    collected_at                        timestamp,
    age_years                             integer,
    sex                                     text,
    analyzer_model                          text,
    assay_name                      text,
    assay_standardcode              text,
    method_name						text,

    indices_json                                 jsonb,     -- агрегированные показатели одним объектом
  
    created_at                                              timestamp DEFAULT now()
);

-- ETL: агрегация нескольких строк fact_measurement_raw в один JSON-объект на кейс
INSERT INTO mart.fact_cbc_case (
    case_id         ,
    order_id                ,
    orderline_id              ,
    
    patient_pseudo_id                ,
    collected_at                        ,
    age_years                             ,
    sex                                     ,
    analyzer_model                          ,
    assay_name                      ,
    assay_standardcode              ,
    method_name						,

    indices_json       
)
SELECT
    uuid_generate_v1(),
    fr.order_id,
    fr.orderline_id,
    
    fr.patient_pseudo_id,
    fr.collected_at,
      CASE
        WHEN dp.birthdate IS NULL OR ol.completiontimestamp IS NULL THEN NULL
        WHEN date_part('year', age(ol.completiontimestamp, dp.birthdate)) NOT BETWEEN 0 AND 120 THEN NULL
        ELSE date_part('year', age(ol.completiontimestamp, dp.birthdate))::integer
    END AS age_years,  
    dp.sex_normalized,
    
    fr.assay_name,
    fr.assay_standardcode,
    
    jsonb_object_agg(
        
        jsonb_build_object(
            'value', fr.value,
            'unit', fr.unit,
            'method',fr.method_name,
            'analyzer',fr.analyzer_name,
            'ref_range', jsonb_build_array(fr.ref_min, fr.ref_max),
            'flag', fr.flag
        )
    ) AS indices_json,
  
FROM mart.fact_measurement_raw fr
JOIN public.orderline ol   ON ol.id = fr.orderline_id
LEFT JOIN mart.dim_patient dp ON dp.patient_pseudo_id = fr.patient_pseudo_id

GROUP BY
    fr.order_id,
    fr.orderline_id,
    
    fr.patient_pseudo_id,
    fr.collected_at,
    age_years,   
    dp.sex_normalized,
    
    fr.assay_name,
    fr.assay_standardcode,
    


-- =====================================================================
-- 5. ИСТОРИЯ И ДЕЛЬТА-ЧЕК (предрасчитанные, отдельная таблица)
-- =====================================================================
CREATE TABLE IF NOT EXISTS mart.fact_patient_history_2026 (
    case_id             uuid REFERENCES mart.fact_cbc_case(case_id),
    historical_results     jsonb,   -- последние N результатов по пациенту (до текущего collected_at)
    delta_check                jsonb    -- {"WBC_delta_pct": ..., "PLT_delta_pct": ...}
);

-- ETL: для каждого текущего кейса ищем до 5 предыдущих результатов того же пациента
-- по тем же показателям и считаем дельту по последнему из них.
-- TODO: логика дельты сейчас упрощённая (по одному показателю за раз через LATERAL) —
-- проверить производительность на реальном объёме данных, при необходимости
-- переписать через оконные функции (LAG) по предварительно развёрнутой таблице.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fact_cbc_case_2026_patient_time
    ON mart.fact_cbc_case_2026 (patient_pseudo_id, collected_at DESC);


ANALYZE mart.fact_cbc_case_2026;


EXPLAIN
INSERT INTO mart.fact_patient_history_2026 (case_id, historical_results, delta_check)
SELECT
    fc.case_id,
    (
        SELECT jsonb_agg(h)
        FROM (
            SELECT jsonb_build_object(
                       'collected_at', prev.collected_at,
                       'indices', prev.indices_json
                   ) AS h
            FROM mart.fact_cbc_case_2026 prev
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
                FROM mart.fact_cbc_case_2026 prev
                WHERE prev.patient_pseudo_id = fc.patient_pseudo_id
                  AND prev.collected_at < fc.collected_at
                ORDER BY prev.collected_at DESC
                LIMIT 1
            ) last_val
            WHERE last_val.indices_json ? key
        ) deltas
    ) AS delta_check
FROM mart.fact_cbc_case_2026 fc
ON CONFLICT DO NOTHING;




-- Проблема исходного варианта: на КАЖДУЮ строку fc выполнялось ДВА
-- независимых обращения к fact_cbc_case_2026 —
--   (a) topN=5 для historical_results,
--   (b) top1 внутри LATERAL, который PostgreSQL, вероятнее всего,
--       пересчитывал заново для КАЖДОГО ключа jsonb_object_keys(fc.indices_json)
--       (т.к. LATERAL стоит внутри подзапроса, коррелированного по key).
-- То есть на строку с ~25 показателями CBC могло уходить не 2, а ~27
-- обращений к таблице.
--
-- Решение: один CROSS JOIN LATERAL на строку fc, который одним проходом
-- отдаёт и массив последних 5 результатов (historical_results), и JSON
-- последнего результата (last_indices_json), из которого затем считается
-- delta_check без повторного похода в таблицу.
-- =====================================================================
 
INSERT INTO mart.fact_patient_history_2026 (case_id, historical_results, delta_check)
SELECT
    fc.case_id,
    hist.historical_results,
    (
        SELECT jsonb_object_agg(key || '_delta_pct', delta_pct)
        FROM (
            SELECT
                key,
                ROUND(
                    ((fc.indices_json -> key ->> 'value')::numeric
                     - (hist.last_indices_json -> key ->> 'value')::numeric)
                    / NULLIF((hist.last_indices_json -> key ->> 'value')::numeric, 0) * 100,
                    1
                ) AS delta_pct
            FROM jsonb_object_keys(fc.indices_json) AS key
            WHERE hist.last_indices_json ? key
              -- защита от деления при нечисловых/пустых значениях
              AND (fc.indices_json -> key ->> 'value') ~ '^-?\d+(\.\d+)?$'
              AND (hist.last_indices_json -> key ->> 'value') ~ '^-?\d+(\.\d+)?$'
        ) deltas
    ) AS delta_check
FROM mart.fact_cbc_case_2026 fc
CROSS JOIN LATERAL (
    SELECT
        jsonb_agg(
            jsonb_build_object('collected_at', t.collected_at, 'indices', t.indices_json)
            ORDER BY t.collected_at DESC
        ) AS historical_results,
        (array_agg(t.indices_json ORDER BY t.collected_at DESC))[1] AS last_indices_json
    FROM (
        SELECT prev.collected_at, prev.indices_json
        FROM mart.fact_cbc_case_2026 prev
        WHERE prev.patient_pseudo_id = fc.patient_pseudo_id
          AND prev.collected_at < fc.collected_at
        ORDER BY prev.collected_at DESC
        LIMIT 5
    ) t
) hist
WHERE hist.historical_results IS NOT NULL   -- пропускаем случаи без истории вообще
ON CONFLICT DO NOTHING;



CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fact_patient_history_2026_case
    ON  mart.fact_patient_history_2026 (case_id);


-- =====================================================================
-- 6. ИТОГОВОЕ ПРЕДСТАВЛЕНИЕ — готовый вид для выгрузки в ML-датасет
-- =====================================================================
CREATE OR REPLACE VIEW mart.v_ml_case_export_2026 AS
SELECT
    fc.case_id,
    fc.order_id,
    fc.orderline_id,
    fc.collected_at,
    fc.patient_pseudo_id,
    fc.age_years,
    fc.sex,
    fc.assay_name,
    fc.assay_standardcode,
    fc.indices_json,
    
    ph.historical_results,
    ph.delta_check
FROM mart.fact_cbc_case_2026 fc
LEFT JOIN mart.fact_patient_history_2026 ph ON ph.case_id = fc.case_id;

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


drop table if exists mart.etl_load_log

CREATE TABLE IF NOT EXISTS mart.etl_load_log (
    target_table   text PRIMARY KEY,
    last_watermark timestamp NOT NULL,
    updated_at     timestamp NOT NULL DEFAULT now()
);




insert into mart.etl_load_log(target_table, last_watermark) values 
   ('mart.dim_patient',             '2000-01-01'),
    ('mart.patient_order_map',       '2000-01-01'),
    ('mart.fact_measurement_raw',    '2000-01-01'),
    ('mart.fact_cbc_case',           '2000-01-01'),
    ('mart.fact_patient_history',    '2000-01-01'),
    ('mart.fact_cbc_case_2026',      '2000-01-01'),
    ('mart.fact_patient_history_2026',    '2000-01-01')

ON CONFLICT (target_table) DO NOTHING;





ALTER TABLE mart.dim_patient
    ADD COLUMN IF NOT EXISTS updated_at timestamp NOT NULL DEFAULT now();



CREATE INDEX IF NOT EXISTS ix_dim_patient_updated_at
    ON mart.dim_patient (updated_at);



[{"indices": {"Уретра - Слизь": {"flag": null, "unit": null, "value": null, "method": "Уретра - Слизь. Микроскопия", "analyser": null, "ref_range": [null, null]}, "Уретра - Флора": {"flag": null, "unit": null, "value": null, "method": "Уретра - Флора. Микроскопия", "analyser": null, "ref_range": [null, null]}, "Влагалище - Слизь": {"flag": null, "unit": null, "value": null, "method": "Влагалище - Слизь. Микроскопия", "analyser": null, "ref_range": [null, null]}, "Влагалище - Флора": {"flag": null, "unit": null, "value": null, "method": "Влагалище - Флора. Микроскопия", "analyser": null, "ref_range": [null, null]}, "Уретра - Эпителий": {"flag": null, "unit": null, "value": null, "method": "Уретра - Эпителий. Микроскопия", "analyser": null, "ref_range": [null, null]}, "Уретра - Лейкоциты": {"flag": null, "unit": null, "value": null, "method": "Уретра - Лейкоциты. Микроскопия", "analyser": null, "ref_range": [null, null]}, "Влагалище - Эпителий": {"flag": null, "unit": null, "value": null, "method": "Влагалище - Эпителий. Микроскопия", "analyser": null, "ref_range": [null, null]}, "Влагалище - Лейкоциты": {"flag": null, "unit": null, "value": null, "method": "Влагалище - Лейкоциты. Микроскопия", "analyser": null, "ref_range": [null, null]}, "Цервикальный канал - Слизь": {"flag": null, "unit": null, "value": null, "method": "Цервикальный канал - Слизь. Микроскопия", "analyser": null, "ref_range": [null, null]}, "Цервикальный канал - Флора": {"flag": null, "unit": null, "value": null, "method": "Цервикальный канал - Флора. Микроскопия", "analyser": null, "ref_range": [null, null]}, "Цервикальный канал - Эпителий": {"flag": null, "unit": null, "value": null, "method": "Цервикальный канал - Эпителий. Микроскопия", "analyser": null, "ref_range": [null, null]}, "Цервикальный канал - Лейкоциты": {"flag": null, "unit": null, "value": null, "method": "Цервикальный канал - Лейкоциты. Микроскопия", "analyser": null, "ref_range": [null, null]}}, "collected_at": "2026-07-09T19:29:24.019967"}, {"indices": {"ВПЧ (тип 16) - количество": {"flag": null, "unit": null, "value": null, "method": "ВПЧ (тип 16) - количество", "analyser": null, "ref_range": [null, null]}, "ВПЧ (тип 18) - количество": {"flag": null, "unit": null, "value": null, "method": "ВПЧ (тип 18) - количество", "analyser": null, "ref_range": [null, null]}, "ВПЧ (тип 31) - количество": {"flag": null, "unit": null, "value": null, "method": "ВПЧ (тип 31) - количество", "analyser": null, "ref_range": [null, null]}, "ВПЧ (тип 33) - количество": {"flag": null, "unit": null, "value": null, "method": "ВПЧ (тип 33) - количество", "analyser": null, "ref_range": [null, null]}, "ВПЧ (тип 35) - количество": {"flag": null, "unit": null, "value": null, "method": "ВПЧ (тип 35) - количество", "analyser": null, "ref_range": [null, null]}, "ВПЧ (тип 39) - количество": {"flag": null, "unit": null, "value": null, "method": "ВПЧ (тип 39) - количество", "analyser": null, "ref_range": [null, null]}, "ВПЧ (тип 45) - количество": {"flag": null, "unit": null, "value": null, "method": "ВПЧ (тип 45) - количество", "analyser": null, "ref_range": [null, null]}, "ВПЧ (тип 51) - количество": {"flag": null, "unit": null, "value": null, "method": "ВПЧ (тип 51) - количество", "analyser": null, "ref_range": [null, null]}, "ВПЧ (тип 52) - количество": {"flag": null, "unit": null, "value": null, "method": "ВПЧ (тип 52) - количество", "analyser": null, "ref_range": [null, null]}, "ВПЧ (тип 56) - количество": {"flag": null, "unit": null, "value": null, "method": "ВПЧ (тип 56) - количество", "analyser": null, "ref_range": [null, null]}, "ВПЧ (тип 58) - количество": {"flag": null, "unit": null, "value": null, "method": "ВПЧ (тип 58) - количество", "analyser": null, "ref_range": [null, null]}, "ВПЧ (тип 59) - количество": {"flag": null, "unit": null, "value": null, "method": "ВПЧ (тип 59) - количество", "analyser": null, "ref_range": [null, null]}}, "collected_at": "2026-07-09T11:23:42.548848"}, {"indices": {"Гомоцистеин": {"flag": null, "unit": "мкмоль/л", "value": 10.8, "method": "Гомоцистеин на Immulite2000 XPI", "analyser": "Immulite 2000 XPI", "ref_range": [5, 12]}}, "collected_at": "2026-07-09T01:06:18.117521"}, {"indices": {"Антитромбин III": {"flag": null, "unit": "%", "value": 123.80000000000001, "method": "Антитромбин III INNOVANCE [Siemens] на Sysmex CS5100", "analyser": "Sysmex CS5100", "ref_range": [83, 118]}}, "collected_at": "2026-07-09T00:50:53.818232"}, {"indices": {"АТ-ТПО (антитела к тиреопероксидазе)": {"flag": null, "unit": "МЕ/мл", "value": null, "method": "АТ-ТПО (антитела к тиреопероксидазе) на MindrayCL6000i-2", "analyser": "MindrayCL6000i-2", "ref_range": [null, 9]}}, "collected_at": "2026-07-09T00:50:53.783502"}]


CREATE OR REPLACE VIEW mart.v_llm_input AS
SELECT
    fc.case_id,
    p.payload,
    md5(p.payload::text) AS input_hash
FROM mart.fact_cbc_case fc
LEFT JOIN mart.dim_patient dp ON dp.patient_pseudo_id = fc.patient_pseudo_id

-- 1) вся история пациента: все исследования, от новых к старым
CROSS JOIN LATERAL (
    SELECT jsonb_agg(
               jsonb_build_object(
                   'collected_at', prev.collected_at,
                   'assay_name',   prev.assay_name,
                   'indices',      prev.indices_json)
               ORDER BY prev.collected_at DESC
           ) AS historical_results
    FROM mart.fact_cbc_case prev
    WHERE prev.patient_pseudo_id = fc.patient_pseudo_id
      AND prev.collected_at     <= fc.collected_at       -- включая другие анализы того же забора
      AND prev.case_id          <> fc.case_id            -- кроме самого кейса
      AND NOT coalesce(dp.needs_manual_review, false)    -- подозрение на склейку разных людей → без истории
) hist

-- 2) дельта-чек по каждому показателю: против последнего значения того же показателя из любого исследования
CROSS JOIN LATERAL (
    SELECT jsonb_object_agg(
               cur.parametr_name || '_delta_pct',
               round(((cur.value - last.value) / nullif(last.value, 0) * 100)::numeric, 1)
           ) AS delta_check
    FROM mart.fact_measurement_raw cur
    CROSS JOIN LATERAL (
        SELECT pr.value
        FROM mart.fact_measurement_raw pr
        WHERE pr.patient_pseudo_id   = cur.patient_pseudo_id
          AND pr.measureparameter_id = cur.measureparameter_id
          AND pr.collected_at        < cur.collected_at
          AND pr.value IS NOT NULL
        ORDER BY pr.collected_at DESC
        LIMIT 1
    ) last
    WHERE cur.orderline_id = fc.orderline_id
      AND cur.value IS NOT NULL
      AND cur.parametr_name IS NOT NULL
      AND NOT coalesce(dp.needs_manual_review, false)
) delta

-- 3) итоговый JSON
CROSS JOIN LATERAL (
    SELECT jsonb_build_object(
        'case_id', fc.case_id,
        'patient_context', jsonb_build_object(
            'patient_pseudo_id', fc.patient_pseudo_id,
            'age_years',         fc.age_years,
            'sex',               fc.sex),
        'current_result', jsonb_build_object(
            'assay_name',         fc.assay_name,
            'assay_standardcode', fc.assay_standardcode,
            'collected_at',       fc.collected_at,
            'indices',            fc.indices_json),
        'historical_results', hist.historical_results,
        'delta_check',        delta.delta_check
    ) AS payload
) p;


















CREATE TEMP TABLE test_cutoff ON COMMIT DROP AS
SELECT max(creationtimestamp) - interval '3 days' AS cutoff
FROM public.orders;

SELECT * FROM test_cutoff;          -- посмотрите, какая дата получилась

-- заказы, созданные после точки отсечения (окно шага 01)
CREATE TEMP TABLE recent_orders ON COMMIT DROP AS
SELECT o.id AS order_id
FROM public.orders o, test_cutoff c
WHERE o.creationtimestamp > c.cutoff;

-- строки заказов, провалидированные после точки отсечения (окно шага 03)
CREATE TEMP TABLE recent_orderlines ON COMMIT DROP AS
SELECT ol.id AS orderline_id
FROM public.orderline ol, test_cutoff c
WHERE coalesce(ol.techvalidated_at, ol.completiontimestamp) > c.cutoff;





-- кейсы
DELETE FROM mart.fact_cbc_case_2026
WHERE orderline_id IN (SELECT orderline_id FROM recent_orderlines);

-- сырые измерения
DELETE FROM mart.fact_measurement_raw
WHERE orderline_id IN (SELECT orderline_id FROM recent_orderlines);

-- карта заказ → пациент
DELETE FROM mart.patient_order_map
WHERE order_id IN (SELECT order_id FROM recent_orders);


UPDATE mart.dim_patient d
SET order_ids = ARRAY(
        SELECT x
        FROM unnest(d.order_ids) AS x
        WHERE x NOT IN (SELECT order_id FROM recent_orders)
        ORDER BY x)
WHERE d.order_ids && ARRAY(SELECT order_id FROM recent_orders);   -- только пациенты со свежими заказами

-- пересчитать счётчик и флаг
UPDATE mart.dim_patient
SET orders_matched_count = cardinality(order_ids),
    needs_manual_review  = cardinality(order_ids) > 15
WHERE orders_matched_count <> cardinality(order_ids);

-- удалить пациентов, у которых заказов не осталось (впервые пришли за последние 3 дня)
DELETE FROM mart.dim_patient
WHERE cardinality(order_ids) = 0;




UPDATE mart.etl_load_log 
SET last_watermark = '2026-08-15 03:43:23.302'




BEGIN;  -- в Airflow не обязательно, но не мешает

WITH bounds AS (
    SELECT last_watermark - interval '1 day' AS lo,   -- перекрытие на поздние коммиты
           now()                             AS hi
    FROM mart.etl_load_log
    WHERE target_table = 'mart.dim_patient'
),
normalized_orders AS (
    SELECT
        o.id                                     AS order_id,
        lower(trim(o.firstname))                 AS fn,
        lower(trim(o.lastname))                  AS ln,
        lower(trim(coalesce(o.middlename, '')))  AS mn,
        o.birthdate::date                        AS bd,
        o.sex                                    AS sex_raw
    FROM public.orders o
    CROSS JOIN bounds b
    WHERE o.deleted = false
      AND o.firstname IS NOT NULL
      AND o.lastname  IS NOT NULL
      AND o.birthdate IS NOT NULL
      AND o.creationtimestamp >  b.lo
      AND o.creationtimestamp <= b.hi
),
grouped AS (
    SELECT
        fn, ln, mn, bd,
        mode() WITHIN GROUP (ORDER BY sex_raw)  AS sex_mode,
        array_agg(order_id ORDER BY order_id)   AS order_ids,
        count(*)                                AS orders_matched_count
    FROM normalized_orders
    GROUP BY fn, ln, mn, bd
)
INSERT INTO mart.dim_patient AS d (
    patient_pseudo_id, natural_key_hash, order_ids,
    birthdate, sex_normalized, orders_matched_count, needs_manual_review
)
SELECT
    'p_' || substr(encode(digest(
        fn || '|' || ln || '|' || mn || '|' || bd::text
        || (SELECT salt_value FROM mart.pseudonymization_config LIMIT 1),
        'sha256'), 'hex'), 1, 12)                                              AS patient_pseudo_id,
    encode(digest(fn || '|' || ln || '|' || mn || '|' || bd::text, 'sha256'), 'hex') AS natural_key_hash,
    order_ids,
    bd,
    sex_mode::text,          -- TODO: расшифровать через enum-справочник
    orders_matched_count,
    orders_matched_count > 15
FROM grouped
ON CONFLICT (natural_key_hash) DO UPDATE
SET order_ids = ARRAY(
        SELECT DISTINCT x
        FROM unnest(d.order_ids || EXCLUDED.order_ids) AS x
        ORDER BY x),
    orders_matched_count = cardinality(ARRAY(
        SELECT DISTINCT unnest(d.order_ids || EXCLUDED.order_ids))),
    needs_manual_review = cardinality(ARRAY(
        SELECT DISTINCT unnest(d.order_ids || EXCLUDED.order_ids))) > 15,
        updated_at = now()
        WHERE NOT (EXCLUDED.order_ids <@ d.order_ids);
        


UPDATE mart.etl_load_log
SET last_watermark = now(),     -- то же значение, что hi: одна транзакция
    updated_at     = now()
WHERE target_table = 'mart.dim_patient';

COMMIT;





BEGIN;

WITH bounds AS (
    SELECT last_watermark - interval '1 day' AS lo,
           now()                             AS hi
    FROM mart.etl_load_log
    WHERE target_table = 'mart.patient_order_map'
),
pairs AS (
    -- один заказ → один пациент; при конфликте берём пациента, обновлённого последним
    SELECT DISTINCT ON (o.order_id)
           o.order_id,
           dp.patient_pseudo_id
    FROM mart.dim_patient dp
    CROSS JOIN bounds b
    CROSS JOIN LATERAL unnest(dp.order_ids) AS o(order_id)
    WHERE dp.updated_at >  b.lo
      AND dp.updated_at <= b.hi
    ORDER BY o.order_id, dp.updated_at DESC
)
INSERT INTO mart.patient_order_map AS m (order_id, patient_pseudo_id)
SELECT order_id, patient_pseudo_id
FROM pairs
ON CONFLICT (order_id) DO UPDATE
SET patient_pseudo_id = EXCLUDED.patient_pseudo_id
WHERE m.patient_pseudo_id IS DISTINCT FROM EXCLUDED.patient_pseudo_id;

UPDATE mart.etl_load_log
SET last_watermark = now(),
    updated_at     = now()
WHERE target_table = 'mart.patient_order_map';

COMMIT;


ROLLBACK


CREATE UNIQUE INDEX IF NOT EXISTS ux_fmr_measurecontext
    ON mart.fact_measurement_raw (measurecontext_id);


BEGIN;

WITH bounds AS (
    SELECT last_watermark - interval '1 day' AS lo,   -- перекрытие на поздние коммиты
           now()                             AS hi
    FROM mart.etl_load_log
    WHERE target_table = 'mart.fact_measurement_raw'
)


INSERT INTO mart.fact_measurement_raw  AS f(
    measurecontext_id, orderline_id, order_id, patient_pseudo_id,
    measureparameter_id,  assay_id , assay_name, assay_standardcode, parametr_name,value, unit,ref_min, ref_max, flag,           -- 'L'/'H'/NULL, из lessflag/moreflag
    resultrefcharstatus_raw,       
    was_entered_manually ,
    
    method_id  ,
    method_name  ,
    analyser_id    ,
    analyser_name ,
    collected_at
    
)
SELECT
    mc.id,
    ol.id,
    
    o.id,
    pat.patient_pseudo_id,
    mc.measureparameter_id,
    a.id,
    a.name,
    a.standardcode,

    dmp.name,
    
    mc.numericvalue,
    munit.name,
    mc.normalminvalue,
    mc.normalmaxvalue,
    CASE
        WHEN mc.lessflag = true THEN 'L'
        WHEN mc.moreflag = true THEN 'H'
        ELSE NULL
    END AS flag,
    mc.resultrefcharstatus,
    mc.wasenteredmanually,
   
    mc.method_id,
    mth.name,
    mth.analyser_id,
    an.name,  -- TODO: связать конкретный лот (reagentlots), а не только reagent_id — нужна доп. логика выбора активного лота на дату
   coalesce(o.registrationtimestamp, o.creationtimestamp) AS collected_at
FROM public.measurecontext mc
JOIN public.orderline ol       ON ol.id = mc.measureorderline_id

JOIN public.orders o             ON o.id = ol.order_id
left join mart.patient_order_map pat  on pat.order_id = o.id

JOIN public.assay a                ON a.id = ol.assay_id
LEFT JOIN public.measureparameter dmp ON dmp.id = mc.measureparameter_id
LEFT JOIN public.measuringunits munit
       ON munit.id = coalesce(mc.measuringunit_id, dmp.measuringunit_id)
       LEFT JOIN  public.method mth ON mth.id = mc.method_id
left join public.analyser an on an.id = mth.analyser_id
WHERE mc.deleted IS NOT TRUE  
  AND ol.deleted = false
  AND o.deleted  = false


 AND coalesce(ol.techvalidated_at, ol.completiontimestamp) >  (SELECT lo FROM bounds)
  AND coalesce(ol.techvalidated_at, ol.completiontimestamp) <= (SELECT hi FROM bounds)
  
  ON CONFLICT (measurecontext_id) DO UPDATE
SET patient_pseudo_id       = EXCLUDED.patient_pseudo_id,
    value                   = EXCLUDED.value,
    unit                    = EXCLUDED.unit,
    ref_min                 = EXCLUDED.ref_min,
    ref_max                 = EXCLUDED.ref_max,
    flag                    = EXCLUDED.flag,
    resultrefcharstatus_raw = EXCLUDED.resultrefcharstatus_raw,
    was_entered_manually    = EXCLUDED.was_entered_manually,
    method_id               = EXCLUDED.method_id,
    method_name             = EXCLUDED.method_name,
    analyser_id             = EXCLUDED.analyser_id,
    analyser_name           = EXCLUDED.analyser_name,
      collected_at            = EXCLUDED.collected_at,
    updated_at = now()
WHERE (f.patient_pseudo_id, f.value, f.unit, f.ref_min, f.ref_max, f.flag,
       f.resultrefcharstatus_raw, f.was_entered_manually,
       f.method_id, f.method_name, f.analyser_id, f.analyser_name, f.collected_at)
      IS DISTINCT FROM
      (EXCLUDED.patient_pseudo_id, EXCLUDED.value, EXCLUDED.unit, EXCLUDED.ref_min, EXCLUDED.ref_max, EXCLUDED.flag,
       EXCLUDED.resultrefcharstatus_raw, EXCLUDED.was_entered_manually,
       EXCLUDED.method_id, EXCLUDED.method_name, EXCLUDED.analyser_id, EXCLUDED.analyser_name, EXCLUDED.collected_at); -- не переписываем неизменившееся


UPDATE mart.etl_load_log
SET last_watermark = now(),     -- то же значение, что hi: одна транзакция
    updated_at     = now()
WHERE target_table = 'mart.fact_measurement_raw';

 

 COMMIT;

 
 
 
 
 -- дубли по orderline_id (должно быть пусто)
SELECT orderline_id, count(*) FROM mart.fact_cbc_case_2026
GROUP BY 1 HAVING count(*) > 1;

CREATE UNIQUE INDEX IF NOT EXISTS ux_fcc2026_orderline
    ON mart.fact_cbc_case_2026 (orderline_id);

ALTER TABLE mart.fact_cbc_case_2026
    ADD COLUMN IF NOT EXISTS updated_at timestamp NOT NULL DEFAULT now();
 
 









BEGIN;

WITH bounds AS (
    SELECT last_watermark - interval '1 day' AS lo,   -- перекрытие на поздние коммиты
           now()                             AS hi
    FROM mart.etl_load_log
    WHERE target_table = 'mart.fact_cbc_case'
),
touched AS (                                             -- 1) какие строки заказа изменились
    SELECT DISTINCT fr.orderline_id
    FROM mart.fact_measurement_raw fr
    CROSS JOIN bounds b
    WHERE fr.updated_at >  b.lo
      AND fr.updated_at <= b.hi
),
agg AS (                                                 -- 2) собираем каждую ЦЕЛИКОМ
    SELECT
        fr.orderline_id,
        fr.order_id,
        fr.patient_pseudo_id,
        fr.collected_at,
        fr.assay_name,
        fr.assay_standardcode,
        
        jsonb_object_agg(
            fr.parametr_name,
            jsonb_build_object(
                'value',     fr.value,
                'unit',      fr.unit,
                'method',    fr.method_name,
                'analyzer',  fr.analyser_name,
                'ref_range', jsonb_build_array(fr.ref_min, fr.ref_max),
                'flag',      fr.flag
            )
        ) AS indices_json
    FROM mart.fact_measurement_raw fr
    JOIN touched t USING (orderline_id)                  -- все измерения изменившихся строк
    WHERE fr.parametr_name IS NOT NULL
      
    GROUP BY fr.orderline_id, fr.order_id, fr.patient_pseudo_id, fr.collected_at,
             fr.assay_name, fr.assay_standardcode
)
INSERT INTO mart.fact_cbc_case_2026 AS c (
    case_id, order_id, orderline_id, patient_pseudo_id, collected_at,
    age_years, sex, assay_name, assay_standardcode,
     indices_json
)
SELECT
    a.orderline_id,                                      -- case_id = orderline_id
    a.order_id,
    a.orderline_id,
    a.patient_pseudo_id,
    a.collected_at,
    CASE
        WHEN dp.birthdate IS NULL OR a.collected_at IS NULL THEN NULL
        WHEN date_part('year', age(a.collected_at, dp.birthdate)) BETWEEN 0 AND 120
            THEN date_part('year', age(a.collected_at, dp.birthdate))::int
    END,
    dp.sex_normalized,
   
    a.assay_name,
    a.assay_standardcode,
    
    a.indices_json
FROM agg a
LEFT JOIN mart.dim_patient dp ON dp.patient_pseudo_id = a.patient_pseudo_id
ON CONFLICT (orderline_id) DO UPDATE
SET patient_pseudo_id = EXCLUDED.patient_pseudo_id,
    collected_at      = EXCLUDED.collected_at,
    age_years         = EXCLUDED.age_years,
    sex               = EXCLUDED.sex,
    
    
    indices_json      = EXCLUDED.indices_json,
    updated_at = now()
WHERE (c.patient_pseudo_id, c.collected_at, c.age_years, c.sex,
        c.indices_json)
      IS DISTINCT FROM
      (EXCLUDED.patient_pseudo_id, EXCLUDED.collected_at, EXCLUDED.age_years, EXCLUDED.sex,
       EXCLUDED.indices_json);


    UPDATE mart.etl_load_log
SET last_watermark = now(),     -- то же значение, что hi: одна транзакция
    updated_at     = now()
WHERE target_table = 'mart.fact_cbc_case';

 

 COMMIT;

    
 

